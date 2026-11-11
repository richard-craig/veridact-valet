#!/usr/bin/env bash
# Deploy the Veridact Valet demo (native Keycloak stack) to one Azure VM, HTTPS on four subdomains.
#
# Run in Azure Cloud Shell (bash) or anywhere the Azure CLI is signed in:
#
#   SUBSCRIPTION="CoffeeMedicine" DNS_ZONE="example.co.za" DNS_ZONE_RG="rg-dns" \
#   ADMIN_CIDR="196.x.x.x/32" ./deploy/azure/deploy.sh
#
# Creates: resource group, static public IP, A records bank/kaya/acme/login.<LABEL>.<DNS_ZONE>, an NSG (80 and 443
# open; 22 from ADMIN_CIDR only), and an Ubuntu VM whose first boot installs Docker, checks out the demo branch,
# writes .env with fresh secrets and starts the stack. Secrets are also saved next to you in valet-demo-secrets.env.
#
# Stop paying when idle:  az vm deallocate -g "$RG" -n "$VM"     Start again:  az vm start -g "$RG" -n "$VM"
# Remove everything:      az group delete -n "$RG"   (and the four DNS records, see the end of this script)
set -euo pipefail

: "${SUBSCRIPTION:?set SUBSCRIPTION (name or id)}"
: "${DNS_ZONE:?set DNS_ZONE, the Azure DNS zone name, e.g. example.co.za}"
: "${DNS_ZONE_RG:?set DNS_ZONE_RG, the resource group that holds the DNS zone}"
: "${ADMIN_CIDR:?set ADMIN_CIDR, your public IP as a CIDR, e.g. 196.25.1.10/32 (Keycloak admin and SSH)}"
LABEL="${LABEL-valet}"                       # hosts: bank.valet.<zone> ...; LABEL="" gives bank.<zone> ...
RG="${RG:-rg-valet-demo}"
LOCATION="${LOCATION:-southafricanorth}"
VM="${VM:-vm-valet-demo}"
VM_SIZE="${VM_SIZE:-Standard_B2ms}"          # 2 vCPU, 8 GiB: Keycloak plus four small services
REPO="${REPO:-https://github.com/richard-craig/veridact-valet.git}"
BRANCH="${BRANCH:-demo/standard-bank-native-consent}"
AUTO_SHUTDOWN_UTC="${AUTO_SHUTDOWN_UTC:-}"    # e.g. 1900 = 21:00 SAST; empty = none

sfx="${LABEL:+.$LABEL}"
BANK_HOST="bank${sfx}.${DNS_ZONE}"; KAYA_HOST="kaya${sfx}.${DNS_ZONE}"
ACME_HOST="acme${sfx}.${DNS_ZONE}"; IDP_HOST="login${sfx}.${DNS_ZONE}"
secret() { openssl rand -base64 36 | tr -d '/+=' | cut -c1-40; }

echo "==> Subscription and resource group"
az account set --subscription "$SUBSCRIPTION"
az group create -n "$RG" -l "$LOCATION" -o none

echo "==> Static public IP"
az network public-ip create -g "$RG" -n "pip-$VM" --sku Standard --allocation-method Static -o none
IP=$(az network public-ip show -g "$RG" -n "pip-$VM" --query ipAddress -o tsv)
echo "    $IP"

echo "==> DNS A records in $DNS_ZONE"
for h in bank kaya acme login; do
  name="${h}${sfx}"
  az network dns record-set a create -g "$DNS_ZONE_RG" -z "$DNS_ZONE" -n "$name" --ttl 300 -o none 2>/dev/null || true
  for old in $(az network dns record-set a show -g "$DNS_ZONE_RG" -z "$DNS_ZONE" -n "$name" --query "ARecords[].ipv4Address" -o tsv 2>/dev/null); do
    [ "$old" = "$IP" ] || az network dns record-set a remove-record -g "$DNS_ZONE_RG" -z "$DNS_ZONE" -n "$name" -a "$old" -o none --keep-empty-record-set
  done
  az network dns record-set a add-record -g "$DNS_ZONE_RG" -z "$DNS_ZONE" -n "$name" -a "$IP" -o none 2>/dev/null || true
  echo "    $name.$DNS_ZONE -> $IP"
done

echo "==> Network security group"
az network nsg create -g "$RG" -n "nsg-$VM" -o none
az network nsg rule create -g "$RG" --nsg-name "nsg-$VM" -n allow-https --priority 100 --access Allow --protocol Tcp \
  --direction Inbound --destination-port-ranges 80 443 --source-address-prefixes Internet -o none
az network nsg rule create -g "$RG" --nsg-name "nsg-$VM" -n allow-ssh-admin --priority 110 --access Allow --protocol Tcp \
  --direction Inbound --destination-port-ranges 22 --source-address-prefixes "$ADMIN_CIDR" -o none

echo "==> Secrets"
SECRETS_FILE="./valet-demo-secrets.env"
if [ -f "$SECRETS_FILE" ]; then
  echo "    reusing $SECRETS_FILE"; . "$SECRETS_FILE"
else
  KC_ADMIN_PASSWORD=$(secret); DEMO_PASSWORD="Thandi-$(secret | cut -c1-10)"; CLAUDE_CLIENT_SECRET=$(secret)
  BANK_CLIENT_SECRET=$(secret); BANK_SESSION_SECRET=$(secret); VALET_HANDOFF_SECRET=$(secret); VALET_INTERNAL_SECRET=$(secret)
  umask 077
  cat > "$SECRETS_FILE" <<EOF
KC_ADMIN_PASSWORD=$KC_ADMIN_PASSWORD
DEMO_PASSWORD=$DEMO_PASSWORD
CLAUDE_CLIENT_SECRET=$CLAUDE_CLIENT_SECRET
BANK_CLIENT_SECRET=$BANK_CLIENT_SECRET
BANK_SESSION_SECRET=$BANK_SESSION_SECRET
VALET_HANDOFF_SECRET=$VALET_HANDOFF_SECRET
VALET_INTERNAL_SECRET=$VALET_INTERNAL_SECRET
EOF
  echo "    saved to $SECRETS_FILE (keep it; re-runs reuse it)"
fi

echo "==> First-boot script"
BOOT=$(mktemp)
cat > "$BOOT" <<BOOTEOF
#!/bin/bash
set -euxo pipefail
exec > /var/log/valet-boot.log 2>&1
curl -fsSL https://get.docker.com | sh
mkdir -p /opt && cd /opt
[ -d valet ] || git clone --branch "$BRANCH" --depth 1 "$REPO" valet
cd valet
umask 077
cat > .env <<ENVEOF
BANK_URL=https://$BANK_HOST
KAYA_URL=https://$KAYA_HOST
ACME_URL=https://$ACME_HOST
IDP_URL=https://$IDP_HOST
BANK_HOST=$BANK_HOST
KAYA_HOST=$KAYA_HOST
ACME_HOST=$ACME_HOST
IDP_HOST=$IDP_HOST
ADMIN_CIDR=$ADMIN_CIDR
$(cat "$SECRETS_FILE")
ENVEOF
cat > /opt/valet/valet.sh <<'OPS'
#!/bin/bash
# valet.sh up | reset | logs | status | update
cd /opt/valet
dc() { docker compose -f docker-compose.native.yml -f docker-compose.vm.yml --env-file .env "\$@"; }
case "\${1:-status}" in
  up) dc up -d --build ;;
  reset) dc down -v --remove-orphans && dc up -d --build ;;
  logs) dc logs -f --tail 100 ;;
  update) git pull --ff-only && dc up -d --build ;;
  *) dc ps ;;
esac
OPS
chmod +x /opt/valet/valet.sh
/opt/valet/valet.sh up
BOOTEOF

echo "==> VM (first boot builds images: allow 8 to 12 minutes)"
az vm create -g "$RG" -n "$VM" -l "$LOCATION" --image Ubuntu2404 --size "$VM_SIZE" \
  --admin-username azureuser --generate-ssh-keys --public-ip-address "pip-$VM" --nsg "nsg-$VM" \
  --os-disk-size-gb 64 --custom-data "$BOOT" -o none
rm -f "$BOOT"
if [ -n "$AUTO_SHUTDOWN_UTC" ]; then az vm auto-shutdown -g "$RG" -n "$VM" --time "$AUTO_SHUTDOWN_UTC" -o none; fi

echo "==> Waiting for https://$BANK_HOST (Docker install, image builds, certificates)"
for i in $(seq 1 90); do
  if curl -fsS -m 5 "https://$BANK_HOST/.well-known/oauth-protected-resource" >/dev/null 2>&1; then ok=1; break; fi
  sleep 10
done
[ "${ok:-}" = 1 ] && echo "    up" || echo "    not up yet: ssh azureuser@$IP 'sudo tail -f /var/log/valet-boot.log'"

cat <<DONE

Veridact Valet demo
  Bank (customer: thandi / \$DEMO_PASSWORD)   https://$BANK_HOST
  Consent API docs                           https://$BANK_HOST/consent/v1/docs
  Kaya (AI agent)                            https://$KAYA_HOST
  Acme Budgeting (third-party app)           https://$ACME_HOST
  Keycloak admin (from $ADMIN_CIDR only)     https://$IDP_HOST/admin   admin / \$KC_ADMIN_PASSWORD
  Claude connector URL                       https://$BANK_HOST/mcp    client id: claude   secret: \$CLAUDE_CLIENT_SECRET
  Secrets                                    $SECRETS_FILE

Check it from your laptop (repository checkout, Python 3.11+):
  BANK_URL=https://$BANK_HOST KAYA_URL=https://$KAYA_HOST ACME_URL=https://$ACME_HOST \\
  DEMO_PASSWORD=... CLAUDE_CLIENT_SECRET=... python scripts/preflight.py

On the VM:  ssh azureuser@$IP   then   sudo /opt/valet/valet.sh status|logs|reset|update
Remove:     az group delete -n $RG --yes
            for h in bank kaya acme login; do az network dns record-set a delete -g $DNS_ZONE_RG -z $DNS_ZONE -n \$h$sfx --yes; done
DONE
