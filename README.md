# Security Reconnaissance Web Application

![Security](https://img.shields.io/badge/Security-Recon-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![Flask](https://img.shields.io/badge/Flask-2.3.2-lightgrey)

A comprehensive web-based security reconnaissance tool that automates subdomain enumeration, port scanning, vulnerability assessment, and security analysis for penetration testers and security researchers.

## Features

- **Subdomain Discovery**
  - Certificate Transparency logs (crt.sh)
  - DNS bruteforcing
  - Passive DNS lookups
  - Subdomain takeover detection

- **Port Scanning**
  - Nmap integration
  - Common port scanning
  - Service version detection
  - Vulnerability script scanning

- **Vulnerability Assessment**
  - XXE injection detection
  - SSRF vulnerability checks
  - CSRF vulnerability checks
  - Security header analysis
  - Exposed file detection

- **Technology Detection**
  - Web server fingerprinting
  - Framework identification
  - Cloud provider detection
  - CDN identification

- **Security Analysis**
  - Risk scoring
  - Attack surface analysis
  - Automated recommendations
  - High-value target identification

## Installation

### Prerequisites

- Linux-based system (Ubuntu/Debian recommended)
- Python 3.8+
- Nmap installed system-wide

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/IlyassCODEX/FOXRECON-v2.0.git
   cd FOXRECON-v2.0
   sudo apt update && sudo apt install -y python3 python3-pip nmap python3-dev build-essential libssl-dev libffi-dev
   pip install -r requirements.txt
   python app.py
'''

For advanced users, you can configure the application with these environment variables:
```bash
  export FLASK_DEBUG=1  # Enable debug mode
  export FLASK_ENV=development  # Set development environment
  export SECRET_KEY='your-secret-key'  # Set application secret key
```
