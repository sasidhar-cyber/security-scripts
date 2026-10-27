# Custom Nmap NSE Security Assessment Toolkit

Original NSE checks and a Python report parser for authorized lab assessments.

## Scripts
- `scripts/http-lab-headers.nse`: selected HTTP security headers.
- `scripts/http-lab-methods.nse`: HTTP OPTIONS / Allow observation.
- `scripts/ftp-lab-anon-check.nse`: bounded anonymous FTP login check.
- `scripts/ssh-lab-banner.nse`: SSH identification banner.
- `parser/report_generator.py`: Nmap XML to Markdown and JSON.

## Run
```bash
nmap -p 80 --script ./scripts/http-lab-headers.nse 127.0.0.1 -oX reports/scan.xml
python3 parser/report_generator.py reports/scan.xml --markdown reports/assessment.md --json reports/assessment.json
```
Replace the target with an explicitly authorized lab IP. These scripts are for limited enumeration; no exploitation or credential guessing is performed. Missing headers and service banners are observations, not automatically confirmed vulnerabilities.
