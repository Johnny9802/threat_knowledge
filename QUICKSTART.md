# 🚀 Quick Start Guide

## Installation (5 minutes)

### 1. Clone and Setup

```bash
cd threat-hunting-playbook

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On macOS/Linux
# OR
venv\Scripts\activate     # On Windows

# Install dependencies
pip install -r requirements.txt

# Install the tool
pip install -e .
```

### 2. Configure AI (Optional but Recommended)

```bash
# Copy environment template
cp .env.example .env

# Get a FREE Groq API key
# 1. Visit: https://console.groq.com/keys
# 2. Sign up (free)
# 3. Create an API key
# 4. Add to .env file:
#    GROQ_API_KEY=your_key_here
```

## First Commands

### List All Playbooks
```bash
hunt list
```

Expected output:
```
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ ID            ┃ Name                      ┃ Technique ┃ Tactic            ┃ Severity ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ PB-T1003-001  │ OS Credential Dumping...  │ T1003     │ credential-access │ CRITICAL │
│ PB-T1059-001  │ Malicious Command Exec... │ T1059     │ execution         │ HIGH     │
│ PB-T1566-001  │ Phishing Email Detection  │ T1566     │ initial-access    │ HIGH     │
└───────────────┴───────────────────────────┴───────────┴───────────────────┴──────────┘
```

### Search for Playbooks
```bash
# Search by keyword
hunt search phishing

# Search by MITRE technique
hunt search --technique T1003

# Search by tactic
hunt search --tactic execution
```

### View Playbook Details
```bash
hunt show PB-T1566-001
```

This displays:
- Full playbook metadata
- Hunt hypothesis
- Detection queries (syntax highlighted!)
- Investigation steps
- False positives
- IOCs and references

### Export Queries

```bash
# Export Splunk query to screen
hunt export PB-T1566-001 --siem splunk

# Export to file
hunt export PB-T1566-001 --siem elastic --output phishing.kql

# Export all queries for a playbook
hunt export-all PB-T1566-001 --output ./my-queries
```

## AI Features (Requires API Key)

### Explain a Playbook
```bash
hunt ai explain PB-T1003-001
```

Get detailed AI explanation of:
- What the attack is
- How the queries work
- False positives
- Investigation steps

### Ask Security Questions
```bash
hunt ai ask "How do I detect mimikatz in Splunk?"
hunt ai ask "What is DCSync attack?"
hunt ai ask "Best practices for credential dumping detection"
```

### Get Investigation Suggestions
```bash
hunt ai suggest --found "User executed suspicious PowerShell with encoded commands"
```

### Generate Query Variants
```bash
# Adapt a playbook for different environment
hunt ai generate PB-T1566-001 --target "Azure AD" --siem elastic
hunt ai generate PB-T1059-001 --target "Linux servers" --siem splunk
```

## Common Workflows

### 1. Investigating a Phishing Alert

```bash
# Find phishing playbooks
hunt search phishing

# View details
hunt show PB-T1566-001

# Export Splunk query
hunt export PB-T1566-001 --siem splunk --output phishing_hunt.spl

# Get AI explanation
hunt ai explain PB-T1566-001

# Ask follow-up questions
hunt ai ask "How do I check if the attachment was executed?"
```

### 2. Building Detection for PowerShell Abuse

```bash
# Search for PowerShell playbooks
hunt search powershell

# View command execution playbook
hunt show PB-T1059-001

# Export for your SIEM
hunt export PB-T1059-001 --siem elastic --output powershell_detection.kql

# Customize for your environment
hunt ai generate PB-T1059-001 --target "Windows 11 endpoints" --siem elastic
```

### 3. Creating a Credential Dumping Alert

```bash
# Find credential access playbooks
hunt search --tactic credential-access

# View the playbook
hunt show PB-T1003-001

# Export all queries
hunt export-all PB-T1003-001 --output ./credential-dumping

# This creates:
# ./credential-dumping/PB-T1003-001/splunk.spl
# ./credential-dumping/PB-T1003-001/elastic.kql
# ./credential-dumping/PB-T1003-001/sigma.yml
```

## Tips & Tricks

### 1. Combine Search Filters
```bash
hunt search --tactic execution --severity high
hunt search --tag powershell --severity critical
```

### 2. Export All Playbooks for Your SIEM
```bash
# Export everything to Splunk format
hunt export-all --siem splunk --output ./splunk-queries

# Export everything to Elastic format
hunt export-all --siem elastic --output ./elastic-queries
```

### 3. View as JSON for Automation
```bash
hunt show PB-T1566-001 --format json | jq '.queries_content.splunk'
```

### 4. Quick MITRE Mapping
```bash
# Search by tactic to see what techniques you cover
hunt search --tactic initial-access
hunt search --tactic execution
hunt search --tactic credential-access
```

## Troubleshooting

### "Command not found: hunt"

Make sure you:
1. Activated the virtual environment: `source venv/bin/activate`
2. Installed the package: `pip install -e .`

### "AI Assistant not configured"

You need to set up an API key:
1. Copy `.env.example` to `.env`
2. Add your Groq or OpenAI API key
3. Groq is recommended (free): https://console.groq.com/keys

### "Playbook not found"

Make sure you're using the correct playbook ID:
- Run `hunt list` to see all available playbooks
- IDs are case-sensitive (e.g., `PB-T1566-001`)

## Next Steps

1. **Explore all playbooks**: `hunt list`
2. **Try the AI features**: Set up API key and run `hunt ai explain PB-T1566-001`
3. **Export queries**: Export to your SIEM and test them
4. **Create your own**: Follow the guide in README.md to add playbooks
5. **Share feedback**: Open an issue on GitHub

## Getting Help

- **Documentation**: See [README.md](README.md)
- **Issues**: Report bugs on GitHub Issues
- **Questions**: Ask in GitHub Discussions

---

**Happy Hunting! 🎯**
