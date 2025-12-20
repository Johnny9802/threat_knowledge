# Contributing to Threat Hunting Playbook

Thank you for your interest in contributing! This document provides guidelines for contributing playbooks, code, and documentation.

## 🎯 Ways to Contribute

1. **Add New Playbooks** - Share your threat hunting knowledge
2. **Improve Existing Playbooks** - Update queries, add context
3. **Fix Bugs** - Report or fix issues
4. **Enhance Features** - Add new capabilities
5. **Improve Documentation** - Help others understand the tool

## 📝 Adding a New Playbook

### Step 1: Create Directory Structure

```bash
cd playbooks/techniques
mkdir -p TXXXX-technique-name/queries
cd TXXXX-technique-name
```

### Step 2: Create `playbook.yaml`

Use this template (must follow `schema.json`):

```yaml
id: PB-TXXXX-001
name: "Descriptive Playbook Name"
description: "One-line description of what this playbook hunts for"

mitre:
  technique: TXXXX
  tactic: tactic-name  # Use lowercase with hyphens
  subtechniques: [TXXXX.001, TXXXX.002]  # Optional

severity: critical|high|medium|low
author: Your Name
created: 2025-12-20
updated: 2025-12-20

data_sources:
  - Windows Event Logs
  - Sysmon
  - EDR Telemetry

hunt_hypothesis: |
  Multi-line hypothesis explaining:
  - What adversary behavior you're hunting
  - Why this technique is used
  - What you expect to find
  - Known false positives

queries:
  splunk: queries/splunk.spl
  elastic: queries/elastic.kql
  sigma: queries/sigma.yml

investigation_steps:
  - First, check X
  - Then, verify Y
  - Finally, validate Z

false_positives:
  - Legitimate process A
  - System operation B
  - Software C doing normal behavior

iocs:
  - type: domain|ip|hash|url|file|registry
    value: "actual value"
    context: "why this is relevant"

references:
  - https://attack.mitre.org/techniques/TXXXX/
  - https://additional-reference.com

tags: [tag1, tag2, tag3]
```

### Step 3: Create Query Files

Create **real, tested queries** in the `queries/` directory:

#### `queries/splunk.spl`
```spl
# Descriptive Comment
# Explains what this query detects

index=your_index sourcetype=your_source
| search suspicious_field=malicious_value
| stats count by field1, field2
| where count > threshold
| table field1, field2, count
```

#### `queries/elastic.kql`
```kql
// Descriptive Comment
// Explains what this query detects

event.category: "process" AND
process.name: suspicious.exe AND
event.action: "start"
```

#### `queries/sigma.yml`
```yaml
title: Detection Rule Title
id: unique-uuid-here
status: production
description: What this rule detects
author: Your Name
date: 2025/12/20
references:
  - https://reference-link.com
tags:
  - attack.tactic_name
  - attack.tXXXX
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    FieldName: 'value'
  condition: selection
falsepositives:
  - Legitimate process
level: high|medium|low
```

### Step 4: Validate Your Playbook

```bash
# Test that it loads correctly
hunt show PB-TXXXX-001

# Verify queries export
hunt export PB-TXXXX-001 --siem splunk
hunt export PB-TXXXX-001 --siem elastic
hunt export PB-TXXXX-001 --siem sigma
```

### Step 5: Submit Pull Request

1. Fork the repository
2. Create a branch: `git checkout -b playbook/TXXXX-technique-name`
3. Add your playbook files
4. Commit: `git commit -m "Add playbook for TXXXX - Technique Name"`
5. Push: `git push origin playbook/TXXXX-technique-name`
6. Open a Pull Request with:
   - Description of the technique
   - Why this playbook is valuable
   - Test results (if any)

## 🐛 Reporting Bugs

### Before Submitting

1. Check if the issue already exists
2. Verify you're using the latest version
3. Test with a clean virtual environment

### Bug Report Template

```markdown
**Description**
Clear description of the bug

**To Reproduce**
1. Run command '...'
2. See error

**Expected Behavior**
What should happen

**Environment**
- OS: [e.g., macOS 14.1]
- Python version: [e.g., 3.11]
- Tool version: [e.g., 1.0.0]

**Error Output**
```
Paste error message here
```
```

## 💡 Feature Requests

We welcome feature ideas! Please open an issue with:

- **Use case**: Why is this feature needed?
- **Proposed solution**: How should it work?
- **Alternatives**: Other approaches you considered
- **Additional context**: Screenshots, examples, etc.

## 🔧 Code Contributions

### Setting Up Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/threat-hunting-playbook.git
cd threat-hunting-playbook

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .

# Install development dependencies
pip install pytest pytest-cov black flake8
```

### Code Style

- Follow PEP 8
- Use type hints
- Add docstrings to functions
- Keep functions focused and small
- Write tests for new features

Format your code:
```bash
black src/ tests/
flake8 src/ tests/
```

### Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_parser.py -v
```

### Commit Messages

Use clear, descriptive commit messages:

```
Add playbook for T1003 credential dumping
Fix parser bug with missing query files
Update README with installation instructions
```

## 📚 Documentation

Help improve documentation:

- Fix typos or unclear instructions
- Add examples
- Improve CLI help text
- Write tutorials or guides

## ✅ Checklist for PR

Before submitting a pull request:

- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] New code has tests
- [ ] Documentation updated (if needed)
- [ ] Commit messages are clear
- [ ] Playbooks follow schema
- [ ] Queries are tested and work

## 🏆 Recognition

Contributors will be:
- Listed in the project README
- Credited in playbook author fields
- Mentioned in release notes

## 📧 Questions?

- **General questions**: Open a GitHub Discussion
- **Bugs**: Open an Issue
- **Security issues**: Email security@example.com

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to the threat hunting community! 🎯**
