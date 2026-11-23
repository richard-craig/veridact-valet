#!/usr/bin/env bash
# Deploy the Veridact Valet demo (native Keycloak stack) to one Azure VM, HTTPS on five subdomains.
#
# Run in Azure Cloud Shell (bash) or anywhere the Azure CLI is signed in:
#
#   SUBSCRIPTION="CoffeeMedicine" DNS_ZONE="example.co.za" DNS_ZONE_RG="rg-dns" \
#   ADMIN_CIDR="196.x.x.x/32" ./deploy/azure/deploy.sh
#
# Creates: resource group, static public IP, A records bank/kaya/acme/login/veridact.<LABEL>.<DNS_ZONE>, an NSG (80 and 443
# open; 22 from ADMIN_CIDR only), and an Ubuntu VM whose first boot installs Docker, checks out the demo branch,
# writes .env with fresh secrets and starts the stack. Secrets are also saved next to you in valet-demo-secrets.env.
#
# KEY_VAULT=1 (recommended): an Azure Key Vault holds the three signing keys (EC P-256, sign-only, never exported)
# and every secret. The VM gets a managed identity that may sign and read secrets and nothing else; its first boot
# reads the secrets from the vault, so none travel in the VM's custom data and none are saved on your machine.
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
REPO="${REPO:-https://github.com/veridactlabs/veridact-valet.git}"
BRANCH="${BRANCH:-main}"
AUTO_SHUTDOWN_UTC="${AUTO_SHUTDOWN_UTC:-}"    # e.g. 1900 = 21:00 SAST; empty = none
KEY_VAULT="${KEY_VAULT:-}"                    # 1 = keys and secrets in Azure Key Vault (see above)
SECRET_NAMES="KC_ADMIN_PASSWORD DEMO_PASSWORD CLAUDE_CLIENT_SECRET BANK_CLIENT_SECRET BANK_SESSION_SECRET VALET_HANDOFF_SECRET VALET_INTERNAL_SECRET VALET_DECISION_SECRET VERIDACT_ADMIN_SECRET CHATGPT_CLIENT_SECRET"
kvname() { echo "$1" | tr 'A-Z_' 'a-z-'; }    # BANK_SESSION_SECRET -> bank-session-secret

sfx="${LABEL:+.$LABEL}"
BANK_HOST="bank${sfx}.${DNS_ZONE}"; KAYA_HOST="kaya${sfx}.${DNS_ZONE}"
ACME_HOST="acme${sfx}.${DNS_ZONE}"; IDP_HOST="login${sfx}.${DNS_ZONE}"; VERIDACT_HOST="veridact${sfx}.${DNS_ZONE}"
secret() { openssl rand -base64 36 | tr -d '/+=' | cut -c1-40; }

echo "==> Subscription and resource group"
az account set --subscription "$SUBSCRIPTION"
az group create -n "$RG" -l "$LOCATION" -o none

echo "==> Static public IP"
az network public-ip create -g "$RG" -n "pip-$VM" --sku Standard --allocation-method Static -o none
IP=$(az network public-ip show -g "$RG" -n "pip-$VM" --query ipAddress -o tsv)
echo "    $IP"

echo "==> DNS A records in $DNS_ZONE"
for h in bank kaya acme login veridact; do
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
if [ -n "$KEY_VAULT" ]; then
  KV_NAME="${KV_NAME:-kv-valet-$(printf '%s' "$SUBSCRIPTION/$RG" | sha256sum | cut -c1-8)}"
  KV_URL="https://$KV_NAME.vault.azure.net"
  echo "    Key Vault $KV_NAME (RBAC; signing keys never leave it)"
  az keyvault show -n "$KV_NAME" -o none 2>/dev/null || \
    az keyvault create -g "$RG" -n "$KV_NAME" -l "$LOCATION" --enable-rbac-authorization true -o none
  KV_ID=$(az keyvault show -n "$KV_NAME" --query id -o tsv)
  ME=$(az ad signed-in-user show --query id -o tsv)
  az role assignment create --assignee-object-id "$ME" --assignee-principal-type User \
    --role "Key Vault Administrator" --scope "$KV_ID" -o none 2>/dev/null || true
  for i in $(seq 1 30); do az keyvault key list --vault-name "$KV_NAME" -o none 2>/dev/null && break; sleep 10; done
  for k in as receipts consent-events; do
    az keyvault key show --vault-name "$KV_NAME" -n "valet-$k" -o none 2>/dev/null || \
      az keyvault key create --vault-name "$KV_NAME" -n "valet-$k" --kty EC --curve P-256 --ops sign verify -o none
  done
  for n in $SECRET_NAMES; do
    v=$(az keyvault secret show --vault-name "$KV_NAME" -n "$(kvname $n)" --query value -o tsv 2>/dev/null || true)
    if [ -z "$v" ]; then
      if [ "$n" = DEMO_PASSWORD ]; then v="Thandi-$(secret | cut -c1-10)"; else v=$(secret); fi
      az keyvault secret set --vault-name "$KV_NAME" -n "$(kvname $n)" --value "$v" -o none
    fi
    printf -v "$n" '%s' "$v"
  done
  echo "    keys valet-as, valet-receipts, valet-consent-events; ${SECRET_NAMES// /, } stored in the vault"
elif [ -f "$SECRETS_FILE" ]; then
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
# Added later (decision service, Veridact attester, ChatGPT client): generated once, also for a secrets file from an earlier run.
# With KEY_VAULT they are in SECRET_NAMES, so the vault creates them and the VM reads them from there.
if [ -z "$KEY_VAULT" ]; then
  for v in VALET_DECISION_SECRET VERIDACT_ADMIN_SECRET CHATGPT_CLIENT_SECRET; do
    if [ -z "${!v:-}" ]; then val=$(secret); printf -v "$v" '%s' "$val"; (umask 077; echo "$v=$val" >> "$SECRETS_FILE"); fi
  done
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
VERIDACT_URL=https://$VERIDACT_HOST
BANK_HOST=$BANK_HOST
KAYA_HOST=$KAYA_HOST
ACME_HOST=$ACME_HOST
IDP_HOST=$IDP_HOST
VERIDACT_HOST=$VERIDACT_HOST
ADMIN_CIDR=$ADMIN_CIDR
ENVEOF
$(if [ -n "$KEY_VAULT" ]; then cat <<KVEOF
# Secrets from Key Vault with the VM's managed identity (retry while its role assignment propagates).
# Tracing off: the boot log must never contain a secret.
set +x
apt-get install -y python3 >/dev/null
kvtoken() { curl -fsS -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'; }
kvget() { curl -fsS -H "Authorization: Bearer \$(kvtoken)" "$KV_URL/secrets/\$1?api-version=7.4" | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])'; }
for i in \$(seq 1 60); do kvget bank-session-secret >/dev/null 2>&1 && break; sleep 10; done
for n in $SECRET_NAMES; do echo "\$n=\$(kvget \$(echo \$n | tr 'A-Z_' 'a-z-'))" >> .env; done
cat >> .env <<KEYSEOF
CLOUD_EXTRAS=1
VALET_KEY_AS=azure-kv:$KV_URL/keys/valet-as
VALET_KEY_RECEIPTS=azure-kv:$KV_URL/keys/valet-receipts
VALET_KEY_CONSENT_EVENTS=azure-kv:$KV_URL/keys/valet-consent-events
KEYSEOF
set -x
KVEOF
else echo "cat >> .env <<'SECEOF'"; cat "$SECRETS_FILE"; echo "SECEOF"; fi)
cat > /opt/valet/valet.sh <<'OPS'
#!/bin/bash
# valet.sh up | reset | logs | status | update
cd /opt/valet
dc() { docker compose -f docker-compose.native.yml -f docker-compose.vm.yml --env-file .env "\$@"; }
case "\${1:-status}" in
  up) dc up -d --build ;;
  # reset wipes demo data but keeps caddydata: Let's Encrypt allows 5 certificates per host name per week
  reset) dc down --remove-orphans && docker volume rm -f valet_valetdata && dc up -d --build ;;
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
  --os-disk-size-gb 64 --custom-data "$BOOT" ${KEY_VAULT:+--assign-identity [system]} -o none
rm -f "$BOOT"
if [ -n "$KEY_VAULT" ]; then
  echo "==> VM identity: sign with the keys and read the secrets, nothing else"
  VM_ID=$(az vm show -g "$RG" -n "$VM" --query identity.principalId -o tsv)
  for role in "Key Vault Crypto User" "Key Vault Secrets User"; do
    az role assignment create --assignee-object-id "$VM_ID" --assignee-principal-type ServicePrincipal \
      --role "$role" --scope "$KV_ID" -o none
  done
fi
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
  ChatGPT connector URL                      https://$BANK_HOST/mcp    client id: chatgpt  secret: \$CHATGPT_CLIENT_SECRET
  Bank operations (decisions, kill switch)   https://$BANK_HOST/ops
  Veridact attester (suspend assistants)     https://$VERIDACT_HOST/admin   secret: \$VERIDACT_ADMIN_SECRET
  Secrets                                    ${KEY_VAULT:+Key Vault $KV_NAME (az keyvault secret show --vault-name $KV_NAME -n demo-password)}${KEY_VAULT:-$SECRETS_FILE}
  Key custody                                https://$BANK_HOST/readyz  ("keys")

Check it from your laptop (repository checkout, Python 3.11+):
  BANK_URL=https://$BANK_HOST KAYA_URL=https://$KAYA_HOST ACME_URL=https://$ACME_HOST \\
  VERIDACT_URL=https://$VERIDACT_HOST VERIDACT_ADMIN_SECRET=... \\
  DEMO_PASSWORD=... CLAUDE_CLIENT_SECRET=... python scripts/preflight.py

On the VM:  ssh azureuser@$IP   then   sudo /opt/valet/valet.sh status|logs|reset|update
Remove:     az group delete -n $RG --yes
            for h in bank kaya acme login veridact; do az network dns record-set a delete -g $DNS_ZONE_RG -z $DNS_ZONE -n \$h$sfx --yes; done
DONE
