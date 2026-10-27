# Lab Validation Plan

Use a private lab network and intentionally configured services. Keep raw XML for every run.

| ID | Lab setup | Script | Expected result |
|---|---|---|---|
| T-HTTP-01 | HTTP server with selected headers | http-lab-headers.nse | Selected headers reported present |
| T-HTTP-02 | HTTP server missing a selected header | http-lab-headers.nse | Missing header noted; no automatic vulnerability claim |
| T-HTTP-03 | OPTIONS response includes Allow | http-lab-methods.nse | Allow header captured |
| T-HTTP-04 | OPTIONS response omits Allow | http-lab-methods.nse | No header noted; methods not assumed disabled |
| T-FTP-01 | FTP server accepts anonymous login | ftp-lab-anon-check.nse | Login acceptance reported; no files accessed |
| T-FTP-02 | FTP server rejects anonymous login | ftp-lab-anon-check.nse | Login not accepted |
| T-SSH-01 | Lab SSH server available | ssh-lab-banner.nse | Identification banner recorded |
| T-REPORT-01 | Nmap XML includes host, port, and script output | report_generator.py | Markdown and JSON generated |

## Commands

Replace LAB_IP with an explicitly authorized lab target:

    nmap -p 80 --script ./scripts/http-lab-headers.nse LAB_IP -oX reports/http-headers.xml
    nmap -p 80 --script ./scripts/http-lab-methods.nse LAB_IP -oX reports/http-methods.xml
    nmap -p 21 --script ./scripts/ftp-lab-anon-check.nse LAB_IP -oX reports/ftp.xml
    nmap -p 22 --script ./scripts/ssh-lab-banner.nse LAB_IP -oX reports/ssh.xml
    python3 parser/report_generator.py reports/http-headers.xml --markdown reports/http-assessment.md --json reports/http-assessment.json

For each test record date/time, tool versions, service configuration, expected and observed output, pass/fail/inconclusive status, and false positives or negatives. Do not scan third-party systems without permission.
