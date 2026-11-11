# Deploy the demo to Azure

One Ubuntu VM in South Africa North runs the native Keycloak stack behind Caddy, with HTTPS on four subdomains of an
Azure DNS zone, all on port 443:

| Host | What |
|---|---|
| `bank.<label>.<zone>` | Marula Bank (fictional): customer app, Consent API docs (`/consent/v1/docs`), MCP gateway (`/mcp`) |
| `kaya.<label>.<zone>` | Kaya, AI agent with its own key |
| `acme.<label>.<zone>` | Acme Budgeting, third-party app |
| `login.<label>.<zone>` | Keycloak; `/admin` and the master realm only from `ADMIN_CIDR` |

The repository is public, so its demo secrets are not used: the script generates every secret (Keycloak admin,
Thandi's password, the bank and Claude client secrets, hand-off and session secrets), and the setup step applies them
to Keycloak on each start.

## Before you start

- Azure CLI signed in to the subscription (Cloud Shell works), with rights to create a resource group, a VM, a public
  IP and an NSG, and to write records in the DNS zone.
- The DNS zone's name and resource group. The zone must be delegated (its NS records live at your registrar), or Let's
  Encrypt cannot issue certificates.
- Your public IP for the admin console and SSH (`curl ifconfig.me` from your laptop, not from Cloud Shell).

## Deploy

```bash
git clone --branch demo/standard-bank-native-consent https://github.com/richard-craig/veridact-valet.git
cd veridact-valet
SUBSCRIPTION="CoffeeMedicine" DNS_ZONE="<your zone>" DNS_ZONE_RG="<zone's resource group>" \
ADMIN_CIDR="<your IP>/32" ./deploy/azure/deploy.sh
```

Optional: `LABEL` (default `valet`; empty for `bank.<zone>`), `RG`, `LOCATION`, `VM_SIZE` (default `Standard_B2ms`),
`AUTO_SHUTDOWN_UTC` (e.g. `1900` for 21:00 SAST). The first boot installs Docker, builds the images and gets
certificates: allow 8 to 12 minutes. Secrets are written to `valet-demo-secrets.env` next to you; keep that file, as
re-running the script reuses it.

## Check it

From a laptop with the repository and Python 3.11+ (`pip install -r requirements.txt mcp`; without the `mcp` SDK the last check is skipped and you get 37/37):

```bash
BANK_URL=https://bank.valet.<zone> KAYA_URL=https://kaya.valet.<zone> ACME_URL=https://acme.valet.<zone> \
DEMO_PASSWORD=<from secrets> CLAUDE_CLIENT_SECRET=<from secrets> python scripts/preflight.py
```

`READY: 38/38` means every journey works end to end through Keycloak over HTTPS.

## Connect Claude

- **Claude app (web, desktop):** Settings → Connectors → Add custom connector. URL `https://bank.valet.<zone>/mcp`;
  under Advanced settings, client ID `claude` and the `CLAUDE_CLIENT_SECRET`. Connect, sign in as `thandi`, choose
  Bill payer.
- **Claude Code:** `MCP_CLIENT_SECRET=<secret> claude mcp add --transport http --client-id claude --client-secret
  --callback-port 33418 marula https://bank.valet.<zone>/mcp`, then `/mcp` → Authenticate.

## Run it

```bash
ssh azureuser@<ip>
sudo /opt/valet/valet.sh status    # containers
sudo /opt/valet/valet.sh reset     # clean slate before a rehearsal or the meeting (secrets and certificates kept)
sudo /opt/valet/valet.sh logs
sudo /opt/valet/valet.sh update    # pull the branch and rebuild
```

Costs: stop the VM when idle with `az vm deallocate -g rg-valet-demo -n vm-valet-demo` (start it with `az vm start`;
the IP and DNS stay). Remove everything with `az group delete -n rg-valet-demo` and the four DNS records (the script
prints the command).

## Limits

This is a demo: Keycloak runs in development mode with its built-in database, there is one VM and no backup, and the
customer and agents are fictional. Do not put real customer data or real bank credentials in it.
