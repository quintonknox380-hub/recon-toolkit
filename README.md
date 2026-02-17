# 🔍 Recon Toolkit — Ethical Hacking Reconnaissance Suite

A modular reconnaissance toolkit for authorized penetration testers and bug bounty hunters.

## ⚠️ Legal Disclaimer
This toolkit is for **authorized testing only** — systems you own or have explicit written permission to test. Unauthorized use may violate CFAA, GDPR, ECPA and equivalent laws.

## Quick Start
pip install -r requirements.txt
python modules/domain_recon.py --domain example.com
python modules/email_recon.py --email user@example.com
python modules/report_generator.py --input results/ --format html
```

---

### 📄 `requirements.txt`
```
python-whois==0.9.4
dnspython==2.4.2
requests==2.31.0
shodan==1.31.0
colorama==0.4.6
pyyaml==6.0.1
jinja2==3.1.2
argparse==1.4.0
tqdm==4.66.1
