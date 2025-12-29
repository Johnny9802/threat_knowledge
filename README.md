# Threat Hunting Playbook

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/Johnny9802/threat_hunting_/releases)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://www.docker.com/)

---

## Executive Summary

**Threat Hunting Playbook** is a centralized knowledge management platform for security operations teams. It combines a comprehensive library of detection playbooks with an interactive MITRE ATT&CK matrix visualization, enabling security analysts to quickly identify coverage gaps and deploy production-ready detection queries across multiple SIEM platforms.

### Key Metrics (v3.0)
| Metric | Value |
|--------|-------|
| Total Playbooks | 49 |
| MITRE Techniques Covered | 48 |
| Framework Coverage | 24.9% |
| Supported SIEMs | 3 (Splunk, Elastic, Sigma) |
| All 14 MITRE Tactics | Covered |

---

## Motivation

Modern Security Operations Centers face significant challenges:

1. **Fragmented Knowledge**: Detection logic is scattered across wikis, tickets, and individual analyst notes
2. **Coverage Blind Spots**: Teams lack visibility into which attack techniques they can actually detect
3. **SIEM Lock-in**: Detection rules are often written for a single platform, limiting portability
4. **Onboarding Friction**: New analysts struggle to understand existing detection capabilities

**Threat Hunting Playbook** addresses these challenges by providing:

- **Single Source of Truth**: All detection playbooks in one searchable, version-controlled repository
- **Visual Coverage Analysis**: Interactive MITRE ATT&CK heatmap showing exactly where gaps exist
- **Multi-SIEM Support**: Every playbook includes queries for Splunk (SPL), Elastic (KQL), and Sigma
- **AI-Powered Assistance**: Get explanations, generate variants, and receive investigation guidance
- **Self-Service Management**: Create, edit, and organize playbooks through web UI or CLI

---

## Features

### Core Platform
- **49 Production-Ready Playbooks** covering all 14 MITRE ATT&CK tactics
- **Interactive MITRE Matrix** with heatmap visualization and drill-down navigation
- **Full CRUD Operations** for playbook management via web UI
- **Multi-SIEM Export** supporting Splunk SPL, Elastic KQL, and Sigma formats
- **RESTful API** for integration with existing security tooling

### AI Assistant (Optional)
- **Playbook Explanations**: Understand attack techniques and detection logic
- **Query Generation**: Create variants for different environments
- **Investigation Guidance**: Get next steps when threats are detected
- **Gap Analysis**: AI-powered recommendations for improving coverage

### Web Interface
- **Dashboard** with coverage statistics and recent activity
- **Playbook Browser** with advanced search and filtering
- **MITRE Matrix View** with interactive coverage visualization
- **Settings Panel** for API and AI configuration

### Sigma Translator
- **Sigma → SPL Conversion**: Convert Sigma detection rules to Splunk SPL queries
- **SPL → Sigma Conversion**: Reverse engineer SPL queries into Sigma format
- **Prerequisites Analysis**: See required log sources, Event IDs, and setup instructions
- **Alternative Sources**: View Windows native vs Sysmon alternatives for each detection
- **Config Warnings**: Automatic checks for missing Sysmon/Audit configurations
- **SigmaHQ Browser**: Browse and import rules directly from the SigmaHQ repository

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/Johnny9802/threat_hunting_.git
cd threat-hunting-playbook

# Start all services
./docker-run.sh up

# Access the application
# API: http://localhost:8000/docs
# Web UI: http://localhost:3000
```

### Option 2: Local Development

```bash
# Clone and setup backend
git clone https://github.com/Johnny9802/threat_hunting_.git
cd threat-hunting-playbook
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start API server
uvicorn api.main:app --reload --port 8000

# In a new terminal, start frontend
cd guiweb
npm install
npm run dev
```

### CLI Usage

```bash
# Install CLI
pip install -e .

# List all playbooks
hunt list

# Search by technique
hunt search --technique T1003

# View playbook details
hunt show PB-T1003-001

# Export query for Splunk
hunt export PB-T1003-001 --siem splunk
```

---

## Architecture

```
threat-hunting-playbook/
├── api/                    # FastAPI backend
│   └── main.py            # API endpoints
├── guiweb/                 # React frontend
│   └── src/
│       ├── components/    # UI components
│       └── services/      # API client
├── playbooks/             # Detection playbooks
│   └── techniques/        # Organized by MITRE technique
│       └── T1003-*/       # Example: Credential Dumping
│           ├── playbook.yaml
│           └── queries/
│               ├── splunk.spl
│               ├── elastic.kql
│               └── sigma.yml
├── src/                   # CLI and core logic
│   ├── cli.py            # Command-line interface
│   ├── parser.py         # YAML parser
│   ├── search.py         # Search engine
│   └── ai_assistant.py   # AI integration
└── scripts/              # Utility scripts
```

---

## Playbook Coverage

### By Tactic

| Tactic | Techniques | Playbooks |
|--------|------------|-----------|
| Reconnaissance | 2 | 2 |
| Resource Development | 1 | 1 |
| Initial Access | 4 | 4 |
| Execution | 6 | 6 |
| Persistence | 5 | 5 |
| Privilege Escalation | 2 | 2 |
| Defense Evasion | 5 | 5 |
| Credential Access | 5 | 5 |
| Discovery | 4 | 4 |
| Lateral Movement | 4 | 4 |
| Collection | 2 | 2 |
| Command and Control | 3 | 3 |
| Exfiltration | 3 | 3 |
| Impact | 2 | 3 |

### Notable Detections

- **Credential Theft**: LSASS dumping, Kerberoasting, password spraying
- **Execution**: PowerShell abuse, WMI execution, malicious scripts
- **Persistence**: Registry run keys, scheduled tasks, services
- **Lateral Movement**: RDP, SMB, PsExec patterns
- **Evasion**: Log clearing, security tool tampering, masquerading
- **Exfiltration**: DNS tunneling, cloud storage abuse, C2 channels

---

## API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/playbooks` | List all playbooks |
| GET | `/api/playbooks/{id}` | Get playbook details |
| POST | `/api/playbooks` | Create new playbook |
| PUT | `/api/playbooks/{id}` | Update playbook |
| DELETE | `/api/playbooks/{id}` | Delete playbook |
| GET | `/api/mitre/gaps` | Coverage gap analysis |
| POST | `/api/ai/explain` | AI playbook explanation |
| POST | `/api/ai/ask` | Ask AI assistant |
| GET | `/api/ai/status` | AI configuration status |

Full API documentation available at `http://localhost:8000/docs`

---

## Configuration

### Environment Variables

```bash
# API Configuration
VITE_API_BASE_URL=http://localhost:8000

# AI Provider (optional)
AI_PROVIDER=groq          # or openai
GROQ_API_KEY=gsk_...      # Free at console.groq.com
OPENAI_API_KEY=sk-...     # platform.openai.com
```

### AI Setup

1. **Groq (Recommended - Free)**
   - Visit https://console.groq.com/keys
   - Create free account and API key
   - Configure in Settings > AI Assistant

2. **OpenAI**
   - Visit https://platform.openai.com/api-keys
   - Create API key
   - Configure in Settings > AI Assistant

---

## Contributing

### Adding a Playbook

1. Create directory: `playbooks/techniques/TXXXX-name/`
2. Add `playbook.yaml` with metadata
3. Add queries in `queries/` subdirectory
4. Test with `hunt show PB-TXXXX-001`
5. Submit pull request

### Playbook Schema

```yaml
id: PB-TXXXX-001
name: "Detection Name"
description: "Brief description"

mitre:
  technique: TXXXX
  tactic: tactic-name
  subtechniques: []

severity: critical|high|medium|low
author: "Your Name"
created: "YYYY-MM-DD"

data_sources:
  - "Required log source"

hunt_hypothesis: |
  What you're looking for and why...

investigation_steps:
  - "Step 1"
  - "Step 2"

false_positives:
  - "Known FP scenario"

tags: [tag1, tag2]
```

---

## Roadmap

### v3.1 (Planned)
- [ ] Splunk App integration for direct deployment
- [ ] Bulk import/export functionality
- [ ] Playbook templates library
- [ ] Team collaboration features

### v3.2 (Planned)
- [ ] Threat intelligence feed integration
- [ ] Automated playbook testing
- [ ] SOAR platform connectors
- [ ] Advanced analytics dashboard

---

## Troubleshooting

### Common Errors and Solutions

#### 1. Docker Container Conflicts

**Error:**
```
Error response from daemon: Conflict. The container name "/threat-hunting-cache" is already in use
```

**Solution:**
If you moved or renamed the project folder, old Docker containers may conflict with new ones. Remove the old containers:

```bash
docker rm -f threat-hunting-proxy threat-hunting-api threat-hunting-db threat-hunting-cache
docker-compose up -d
```

#### 2. Frontend "Failed to load playbooks" / Error 500

**Possible Causes:**
- Docker containers not running
- API service not healthy

**Solution:**
```bash
# Check container status
docker-compose ps

# If containers are not running, start them
docker-compose up -d

# Check API logs for errors
docker-compose logs api
```

#### 3. Frontend "Failed to save configuration to server"

**Cause:** The backend API is not reachable.

**Solution:**
1. Ensure all Docker services are running: `docker-compose ps`
2. Check if API responds: `curl http://localhost:8001/health`
3. If using the development frontend, ensure `npm run dev` is running

#### 4. "GROQ_API_KEY" or "OPENAI_API_KEY" warnings

**Warning:**
```
The "GROQ_API_KEY" variable is not set. Defaulting to a blank string.
```

**Note:** This is just a warning and does not prevent the application from running. AI features will be disabled until you configure an API key in Settings.

To enable AI features, create a `.env` file:
```bash
cp .env.example .env
# Edit .env and add your API keys
```

#### 5. Frontend Development Server Errors

**Error:**
```
[vite] Failed to resolve import "../lib/utils"
```

**Solution:** Make sure you have all dependencies installed:
```bash
cd guiweb
npm install
npm run dev
```

#### 6. API Not Accessible on Port 80

**Issue:** Going to `http://localhost` shows API JSON instead of the web interface.

**Explanation:** In Docker mode, Nginx proxies all requests to the API. The frontend needs to be built and included in the Docker image, or run separately in development mode.

**For Development:**
```bash
# Terminal 1: Run Docker services
docker-compose up -d

# Terminal 2: Run frontend dev server
cd guiweb
npm install
npm run dev

# Access frontend at http://localhost:3000
```

#### 7. Database Connection Issues

**Error:**
```
sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) could not connect to server
```

**Solution:**
```bash
# Wait for PostgreSQL to be healthy
docker-compose up -d
sleep 10

# Verify database is running
docker-compose logs postgres

# If needed, restart all services
docker-compose down
docker-compose up -d
```

### Port Reference

| Service | Port | Description |
|---------|------|-------------|
| Nginx (Docker) | 80, 443 | Reverse proxy |
| API | 8001 | FastAPI backend |
| Frontend (dev) | 3000 | Vite dev server |
| PostgreSQL | 5433 | Database |
| Redis | 6380 | Cache |

### Health Checks

```bash
# API health
curl http://localhost:8001/health

# Docker services status
docker-compose ps

# View all logs
docker-compose logs -f
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Links

- **Repository**: https://github.com/Johnny9802/threat_hunting_
- **Issues**: https://github.com/Johnny9802/threat_hunting_/issues
- **Documentation**: [NEW_FEATURES.md](NEW_FEATURES.md)

---

**Built for Security Teams** | Version 3.0.0
