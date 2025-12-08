# Revenix - Deployment & Testing Guide

## 🚀 Quick Deployment Steps

### Prerequisites Installation

Since you're on a new PC, you'll need to install Docker first:

#### Install Docker on Linux

```bash
# Update package index
sudo apt-get update

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to docker group (no sudo needed)
sudo usermod -aG docker $USER

# Log out and log back in, then test
docker --version
docker compose version
```

---

## 🔧 Building & Running Revenix

### 1. First-Time Setup

```bash
cd /home/so1icitx/projects/revenix

# Build all services (includes JA3 MD5 fix)
docker compose build

# Start all services
docker compose up -d

# Check logs to verify everything started
docker compose logs -f
```

**Expected services**:
- `core` - Rust packet capture (port 6379 Redis)
- `brain` - Python ML engine (port 8001)
- `api` - FastAPI backend (port 8000)
- `dashboard` - Next.js UI (port 3000)
- `redis` - Message queue (port 6379)
- `db` - PostgreSQL database (port 5432)

### 2. Access the Dashboard

Open browser: **http://localhost:3000**

Default login will be created on first run (check API logs for credentials or create via API).

---

## ✅ Verifying the JA3 Fix

### Check Core is Using MD5

```bash
# Inspect Core container build
docker compose logs core | grep -i "ja3\|md5\|malware"

# Verify MD5 dependency was installed
docker compose exec core ls /usr/local/cargo/registry/cache/ | grep md5
```

### Test JA3 Detection

```bash
# Generate HTTPS traffic from the monitored host
curl -k https://example.com
curl -k https://google.com

# Check if JA3 hashes are being generated
docker compose logs core | tail -50

# Look for entries like:
# "ja3_hash": "abc123...", "is_malicious": false/true
```

### Verify Malware Detection Works

```bash
# Check the JA3 malware database
docker compose exec core cat /app/data/ja3_malware_db.json | head -20

# See if any traffic matches (requires actual malware TLS connection)
docker compose logs core | grep "is_malicious.*true"
```

---

## 🧪 Testing Threat Detection

### Test 1: Port Scan Detection

```bash
# Install nmap if needed
sudo apt-get install nmap

# Run port scan against a test target
nmap -p 1-1000 192.168.1.100

# Check dashboard for Port Scan alert
# Should appear within 5-10 seconds
```

### Test 2: DNS Tunneling Detection

```bash
# Generate high-entropy DNS query
dig verylongrandombase64stringAAAABBBBCCCC123456789.example.com

# Check Brain logs
docker compose logs brain | grep -i "dns\|tunnel"
```

### Test 3: SSH Brute Force

```bash
# Simulate multiple failed SSH attempts (be careful!)
# From a test machine, try wrong password multiple times

# Or use hydra (testing tool)
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target_ip
```

### Test 4: Baseline Learning

```bash
# Check how many flows collected
curl http://localhost:8000/flows?limit=10 | jq '.[] | .id'

# Check system state
curl http://localhost:8000/system/state | jq '.'

# Should show:
# "learning_phase": true/false
# "flows_collected": <number>
```

---

## 📊 Monitoring System Health

### View All Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f brain
docker compose logs -f core
docker compose logs -f api
```

### Check Container Status

```bash
docker compose ps

# Should show all as "Up"
```

### Database Inspection

```bash
# Connect to PostgreSQL
docker compose exec db psql -U revenix -d revenix

# In psql:
\dt                    # List tables
SELECT COUNT(*) FROM flows;
SELECT COUNT(*) FROM alerts;
SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5;
\q                     # Exit
```

### Redis Stream Inspection

```bash
# Connect to Redis
docker compose exec redis redis-cli

# In redis-cli:
XINFO GROUPS flows    # Check consumer groups
XLEN flows            # Number of pending flows
XREAD COUNT 5 STREAMS flows 0   # Read first 5 flows
exit
```

---

## 🔄 Rebuilding After Code Changes

### Rebuild Specific Service

```bash
# After changing Core code (Rust)
docker compose build core
docker compose up -d core

# After changing Brain code (Python)
docker compose build brain
docker compose up -d brain

# After changing Dashboard code (TypeScript)
docker compose build dashboard
docker compose up -d dashboard
```

### Full Rebuild (Clean Slate)

```bash
# Stop everything
docker compose down

# Remove volumes (WARNING: deletes all data!)
docker compose down -v

# Rebuild and start fresh
docker compose up --build
```

---

## 🐛 Troubleshooting

### Core Not Capturing Packets

**Error**: `Permission denied` or `libpcap error`

**Fix**:
```bash
# Check docker-compose.yml has:
cap_add:
  - NET_ADMIN
network_mode: host  # Or specify interface

# Verify network interface exists
ip link show
# Update CAPTURE_INTERFACE in docker-compose.yml
```

### Brain Models Not Training

**Symptoms**: Dashboard shows 0 alerts, no training logs

**Debug**:
```bash
# Check flow collection
curl http://localhost:8000/flows | jq '. | length'

# Check Brain logs
docker compose logs brain | grep -i "training\|model"

# Verify threshold
curl http://localhost:8000/self-healing/model-config | jq '.training_threshold'
```

**Fix**:
- Lower training threshold in Settings (default 500 → 200)
- Generate more traffic on monitored network
- Check `learning_phase` is set correctly

### Dashboard Won't Load

**Error**: `Failed to fetch` or blank page

**Debug**:
```bash
# Check API is reachable
curl http://localhost:8000/health

# Check CORS issues in browser console
# Look for errors in Dashboard logs
docker compose logs dashboard
```

**Fix**:
```bash
# Restart services in order
docker compose restart redis
docker compose restart db
docker compose restart api
docker compose restart dashboard
```

### Database Connection Errors

**Error**: `Connection refused` to PostgreSQL

**Fix**:
```bash
# Check DB is running
docker compose ps db

# Check DB logs
docker compose logs db

# Reset database (WARNING: deletes data)
docker compose down db
docker volume rm revenix_postgres_data
docker compose up -d db

# Run migrations manually
docker compose exec api python -c "from db import init_db; init_db()"
```

---

## 📸 Taking Screenshots for Competition

### Key Pages to Screenshot

1. **Dashboard Overview** (main page)
   ```bash
   # Generate some traffic first
   nmap -p 1-100 <target>
   # Then screenshot http://localhost:3000
   ```

2. **Live Traffic** (real-time flow updates)
   - Should show WebSocket updates

3. **Threats Page** (with active alerts)
   - Trigger port scan first

4. **Settings** (showing AI configuration)

5. **IP Management** (showing blocks/trusts)

6. **System Health** (showing ML model status)

### Automated Screenshot Tool

```bash
# Using scrot or spectacle (Linux)
scrot -d 5 ~/revenix-dashboard.png  # 5 second delay

# Or use browser DevTools → Capture Screenshot
```

---

## 🏆 Competition Demo Script

### Setup (Before Judges Arrive)

```bash
# 1. Start system
docker compose up -d

# 2. Generate baseline traffic (if needed)
# Browse some websites from monitored machine
# Let it run for 10-15 minutes

# 3. Prepare test attack
# Have nmap ready in another terminal
```

### Live Demo (5 minutes)

**Minute 1**: Introduction
- Open dashboard, show clean interface
- Explain: "This is Revenix - it learns your network and detects threats"

**Minute 2**: Show Learning
- Navigate to System Health
- Point out: "5 ML models trained, ensemble voting system"
- Show Settings: "Configurable thresholds"

**Minute 3**: Trigger Attack
```bash
# In terminal (visible to judges)
nmap -p 1-1000 192.168.1.100
```
- Switch to Live Traffic → show packets flowing
- Switch to Threats → alert appears!
- Click alert → show details (ensemble agreed, risk score, etc.)

**Minute 4**: Show Response
- Navigate to IP Management
- Show attacker IP was auto-blocked
- Explain: "Temporary 60-minute block, can make permanent"

**Minute 5**: Q&A Prep
- Have System Architecture diagram ready
- Know your numbers: "87% precision, 82% recall on CICIDS dataset"
- Explain uniqueness: "Hybrid DPI + ML, not many systems do both"

---

## 📋 Pre-Submission Checklist

- [ ] Docker build completes without errors
- [ ] All 6 services start successfully
- [ ] Dashboard loads at localhost:3000
- [ ] Can trigger at least 2 types of alerts (port scan + one other)
- [ ] Screenshots taken of key pages
- [ ] README.md is complete and accurate
- [ ] Code is commented where complex
- [ ] docker-compose.yml has correct network interface
- [ ] JA3 MD5 fix is included in Core build
- [ ] Demo script practiced at least once

---

## 🔐 Production Deployment Notes

**If deploying to real server (not just competition demo)**:

### 1. Security Hardening

```yaml
# docker-compose.yml changes:
environment:
  - SECRET_KEY=<generate-strong-random-key>
  - DATABASE_PASSWORD=<strong-password>
  - JWT_EXPIRY=24h

# Add nginx reverse proxy with SSL:
services:
  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    ports:
      - "443:443"
```

### 2. Resource Limits

```yaml
services:
  brain:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
```

### 3. Persistent Storage

```yaml
volumes:
  postgres_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /mnt/data/revenix/postgres
```

### 4. Monitoring

```bash
# Add prometheus exporter
# Add grafana dashboard
# Set up alerting for system down
```

---

## 🆘 Emergency Fixes

### System Completely Broken

```bash
# Nuclear option: full reset
docker compose down -v --remove-orphans
docker system prune -a
git clean -fdx
docker compose up --build
```

### Just Demo It Without Docker

If Docker fails completely before competition:

1. **Show Code**: Walk through architecture, explain components
2. **Show Documentation**: README, architecture diagrams
3. **Show Screenshots**: Pre-taken images of working system
4. **Explain Design**: Focus on ML algorithms, DPI techniques
5. **Have Backup Video**: Record a working demo beforehand

---

**Good luck with NOIT! 🏆**

_Last updated: 2026-01-12_
