# Methodology and Safe Use

## Scope first
1. Obtain authorization and define target IPs, ports, testing window, and exclusions.
2. Prefer isolated VMs or containers with intentionally configured services.
3. Start with a small number of ports and scripts; follow approved rate limits.
4. Preserve raw Nmap XML output for reproducibility.

## Checks
- **HTTP headers:** requests the root path and records selected response headers.
- **HTTP OPTIONS:** sends one OPTIONS request to the root path and records Allow if returned.
- **FTP anonymous login:** tests the conventional anonymous identity with a fixed test string. It does not enumerate or transfer files.
- **SSH banner:** records the service identification string; it does not authenticate.

## Severity guidance
These scripts collect observations. A human reviewer should assign severity after considering exposure, impact, compensating controls, context, and confidence. Missing browser headers may be Informational/Low; anonymous FTP acceptance may be more serious if sensitive files are exposed, which this script does not test; a banner is usually informational. Do not claim a vulnerability solely from a banner or missing header.

## Evidence quality
Record target, port, timestamp, script version, exact output, expected and observed behavior, and a repeatable validation step. Distinguish confirmed, suspected, and inconclusive results.

## Limitations
- HTTP checks inspect only the root path; redirects and virtual hosts may affect results.
- OPTIONS output does not prove all methods are usable.
- Validate response-header behavior against the installed Nmap version.
- FTP servers may use multi-line replies or unusual policies; inconclusive results need manual review.
- SSH identification strings can be customized and do not independently prove a vulnerable version.
- The report generator parses observations; it does not calculate CVSS or automatically assert exploitability.

## Safety
Use only on systems you own or have explicit permission to assess. These scripts are for limited enumeration, not exploitation, credential attacks, or configuration changes.
