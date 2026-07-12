# Honeypot & SIEM Setup

This guide covers two independent optional modules:

1. **Honeypot collection** — deploy a Cowrie SSH honeypot that feeds events into Pythia automatically
2. **SIEM integration** — connect Pythia's detection rules to Wazuh (or Splunk/Elastic) for live alerting

Both can run locally for testing or on a dedicated VPS for real attacker traffic.

---

## Part 1 — Honeypot Collection

### Architecture

```
Internet ──→ VPS (Cowrie SSH honeypot)
                  │ cowrie.json log
                  ▼
         honeypot-forwarder (Python)
                  │ POST /v1/honeypot/events/bulk
                  ▼
         Pythia (enrichment, clustering, Sigma generation)
```

The forwarder tails Cowrie's JSON log and batches events to Pythia every 5 seconds. Pythia enriches each event with GeoIP, ASN, and (optionally) AbuseIPDB/GreyNoise/VirusTotal, then clusters IPs into campaigns and auto-generates Sigma detection rules.

---

### Option A — Local testing (no VPS)

Run everything on the same machine as Pythia:

```bash
# Terminal 1 — start Pythia
docker compose -f docker-compose.yml up -d

# Terminal 2 — start the honeypot stack alongside Pythia
docker compose -f docker-compose.yml -f docker-compose.honeypot.yml up -d
```

The `cowrie` container listens on host port 22 (SSH) and 23 (Telnet). To avoid conflicting with your real SSH, either move your real SSH to another port first, or change the ports in `docker-compose.honeypot.yml`.

Test it by SSH-ing to localhost:
```bash
ssh root@localhost   # Cowrie will catch it; real SSH is now on 64222
```

---

### Option B — Dedicated VPS (recommended for real traffic)

A VPS with a public IP will attract real internet scanners within minutes.

#### 1. Provision a VPS

Any cloud provider works. Minimum specs: 1 vCPU, 1 GB RAM, Ubuntu 22.04.

Recommended: Hetzner CX11 (~$4/month), Vultr, or DigitalOcean.

#### 2. Move your real SSH off port 22

Do this **before** deploying Cowrie, or you'll lock yourself out:

```bash
# On the VPS — edit sshd_config
sudo sed -i 's/#Port 22/Port 64222/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Verify you can still connect on the new port from a second terminal
ssh -p 64222 user@your-vps-ip

# Then open the new port in your firewall
sudo ufw allow 64222/tcp
sudo ufw allow 22/tcp    # will be Cowrie
sudo ufw allow 23/tcp    # will be Cowrie Telnet
```

#### 3. Install Docker on the VPS

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

#### 4. Copy the honeypot files to the VPS

From your local machine:

```bash
scp -P 64222 -r docker/ docker-compose.honeypot.yml user@your-vps-ip:~/pythia-honeypot/
```

#### 5. Set environment variables on the VPS

Create `~/pythia-honeypot/.env`:

```env
# URL of your Pythia instance (over Tailscale if using a private tunnel)
PYTHIA_URL=https://pythia.your-domain.com
# Or over Tailscale:
# PYTHIA_URL=http://100.64.x.x:8000

# Your Pythia API key (from .env PYTHIA_API_KEY)
PYTHIA_API_KEY=your-api-key-here
```

#### 6. Start the honeypot

```bash
cd ~/pythia-honeypot
docker compose -f docker-compose.honeypot.yml up -d
```

#### 7. (Optional) Connect over Tailscale

Tailscale gives the VPS a private IP that Pythia can reach without exposing the API publicly:

```bash
# On the VPS
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# On your Pythia host
sudo tailscale up

# Use the Tailscale IP in .env on the VPS:
# PYTHIA_URL=http://100.64.x.x:8000
```

---

### Verify honeypot is working

1. Open Pythia → **Honeypot** page
2. Check the **Live Feed** tab — events should appear within seconds of an SSH connection attempt
3. After a few minutes, the **Campaigns** tab will show clustered attacker groups
4. Check logs: `docker logs pythia-honeypot-forwarder -f`

---

### Honeypot configuration

The Cowrie config is at `docker/cowrie/cowrie.cfg`. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `hostname` | `svr01` | Fake hostname attackers see |
| `version` | `OpenSSH_8.4p1 Debian` | SSH banner string |
| `ttylog` | `true` | Record full TTY sessions |

To add a fake filesystem or fake commands, mount additional volumes — see [Cowrie docs](https://cowrie.readthedocs.io/).

---

## Part 2 — SIEM Integration (Wazuh)

### Architecture

```
Pythia (generates Sigma rules)
        │ POST /v1/siem/rules/{id}/deploy
        ▼
Wazuh Manager (stores rules)
        │ alert webhook
        ▼
Pythia POST /v1/siem/alerts/receive
        │ auto-triage
        ▼
Pythia Operations page (alert queue)
```

---

### Start Wazuh

Wazuh requires ~4 GB RAM. On a machine that can spare it:

```bash
docker compose -f docker-compose.siem.yml up -d
```

First startup takes 3–5 minutes. Watch progress:

```bash
docker compose -f docker-compose.siem.yml logs -f
```

When ready, the dashboard is at: **https://localhost** (accept the self-signed cert)

Default credentials:
- Dashboard: `admin` / `SecretPassword`
- API: `wazuh-wui` / `MyS3cr37P450r.*-`

**Change these passwords before exposing Wazuh to a network.**

---

### Connect Pythia to Wazuh

Add to your `.env`:

```env
PYTHIA_SIEM_TYPE=wazuh
PYTHIA_SIEM_URL=https://localhost:55000
PYTHIA_SIEM_USERNAME=wazuh-wui
PYTHIA_SIEM_PASSWORD=MyS3cr37P450r.*-
```

Restart Pythia:

```bash
docker compose restart pythia
```

Verify the connection from Pythia's **Operations** page — the SIEM status bar should show **Connected**.

---

### Deploy detection rules

1. Go to **Operations → Rule Deployment** in Pythia
2. Click **Deploy All** to push all active Sigma rules to Wazuh
3. Individual rules can be deployed or removed per-row

Pythia uses `sigma-cli` to convert Sigma YAML → Wazuh XML rules before deploying. If `sigma-cli` isn't installed in the Pythia container, install it:

```bash
pip install sigma-cli
sigma plugin install wazuh
```

Or add to `pyproject.toml` optional dependencies and rebuild the Docker image.

---

### Configure Wazuh to webhook back to Pythia

This lets Wazuh alert Pythia when a rule fires, so alerts appear in the **Operations → Alert Queue**.

1. SSH into the Wazuh manager container:

```bash
docker exec -it $(docker ps -qf name=wazuh.manager) bash
```

2. Edit `/var/ossec/etc/ossec.conf` and add an integration block inside `<ossec_config>`:

```xml
<integration>
  <name>custom-pythia</name>
  <hook_url>http://YOUR_PYTHIA_HOST:8000/v1/siem/alerts/receive</hook_url>
  <api_key>YOUR_PYTHIA_API_KEY</api_key>
  <alert_format>json</alert_format>
  <level>3</level>
</integration>
```

3. Create the integration script at `/var/ossec/integrations/custom-pythia`:

```bash
#!/usr/bin/env python3
import sys, json, urllib.request

alert_file = sys.argv[1]
api_key = sys.argv[3]
hook_url = sys.argv[2]

with open(alert_file) as f:
    alert = json.load(f)

req = urllib.request.Request(
    hook_url,
    data=json.dumps(alert).encode(),
    headers={"Content-Type": "application/json", "X-API-Key": api_key},
    method="POST",
)
urllib.request.urlopen(req, timeout=10)
```

```bash
chmod 755 /var/ossec/integrations/custom-pythia
chown root:wazuh /var/ossec/integrations/custom-pythia
```

4. Restart the Wazuh manager:

```bash
/var/ossec/bin/wazuh-control restart
```

Alerts from Wazuh now appear in Pythia's **Operations → Alert Queue** for triage.

---

### Alternative SIEMs

#### Splunk

```env
PYTHIA_SIEM_TYPE=splunk
PYTHIA_SIEM_URL=https://your-splunk-host:8089
PYTHIA_SIEM_USERNAME=admin
PYTHIA_SIEM_PASSWORD=your-splunk-password
```

Pythia converts Sigma rules to SPL saved searches and deploys them to the `pythia_detections` app.

#### Elastic / OpenSearch

```env
PYTHIA_SIEM_TYPE=elastic
PYTHIA_SIEM_URL=https://your-elastic-host:9200
PYTHIA_SIEM_API_TOKEN=your-elastic-api-key
```

Pythia converts Sigma rules to EQL and deploys them as Elastic detection rules.

---

## Environment variables reference

| Variable | Default | Description |
|----------|---------|-------------|
| `PYTHIA_HONEYPOT_INGEST_ENABLED` | `true` | Enable `/v1/honeypot` endpoints |
| `PYTHIA_ENABLE_SCHEDULER` | `true` | Enable campaign detection + daily reports |
| `PYTHIA_MAXMIND_DB_PATH` | — | Path to `GeoLite2-City.mmdb` |
| `PYTHIA_MAXMIND_ASN_DB_PATH` | — | Path to `GeoLite2-ASN.mmdb` |
| `PYTHIA_ABUSEIPDB_API_KEY` | — | AbuseIPDB enrichment (free: 1000 req/day) |
| `PYTHIA_GREYNOISE_API_KEY` | — | GreyNoise enrichment (free community tier) |
| `PYTHIA_VIRUSTOTAL_API_KEY` | — | VirusTotal enrichment (free: 500 req/day) |
| `PYTHIA_SIEM_TYPE` | `wazuh` | `wazuh`, `splunk`, or `elastic` |
| `PYTHIA_SIEM_URL` | — | Base URL of SIEM API |
| `PYTHIA_SIEM_USERNAME` | — | SIEM API username |
| `PYTHIA_SIEM_PASSWORD` | — | SIEM API password |
| `PYTHIA_SIEM_API_TOKEN` | — | API token (Elastic only) |

---

## Troubleshooting

**Forwarder sends events but none appear in Pythia**
- Check `PYTHIA_HONEYPOT_INGEST_ENABLED=true` in `.env`
- Check the API key matches: `PYTHIA_API_KEY` in `.env` == `PYTHIA_API_KEY` in the forwarder's env
- Check Pythia logs: `docker compose logs pythia -f`

**GeoIP enrichment not working**
- Confirm the `.mmdb` files exist at the paths in `PYTHIA_MAXMIND_DB_PATH` and `PYTHIA_MAXMIND_ASN_DB_PATH`
- Test: `python -c "import geoip2.database; r=geoip2.database.Reader('path/to/GeoLite2-City.mmdb'); print(r.city('8.8.8.8').country.iso_code)"`

**Wazuh dashboard unreachable**
- Wait longer — first startup takes 3–5 minutes
- Check: `docker compose -f docker-compose.siem.yml ps` — all three services should be `Up`
- Check logs: `docker compose -f docker-compose.siem.yml logs wazuh.indexer`

**Sigma rule deployment fails**
- Install sigma-cli: `pip install sigma-cli && sigma plugin install wazuh`
- Check SIEM credentials in `.env`
- Try the connection test from the Operations page status bar

**Campaign detection not running**
- Ensure `PYTHIA_ENABLE_SCHEDULER=true`
- Campaign detection runs every 15 minutes; check scheduler logs in Pythia output
