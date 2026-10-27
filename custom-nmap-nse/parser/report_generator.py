#!/usr/bin/env python3
"""Convert Nmap XML output into review-friendly Markdown and JSON."""
import argparse, json, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

def parse_xml(path):
    root = ET.parse(path).getroot()
    data = {"source_file": str(path), "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "nmap_version": root.attrib.get("version", "unknown"), "scan_args": root.attrib.get("args", ""), "hosts": []}
    for host in root.findall("host"):
        status = host.find("status")
        item = {"status": status.attrib.get("state", "unknown") if status is not None else "unknown",
                "addresses": [{"type": a.attrib.get("addrtype", "unknown"), "address": a.attrib.get("addr", "")} for a in host.findall("address")],
                "hostnames": [h.attrib.get("name", "") for h in host.findall("./hostnames/hostname")], "ports": []}
        for port in host.findall("./ports/port"):
            state, service = port.find("state"), port.find("service")
            scripts = [{"id": s.attrib.get("id", "unknown"), "output": s.attrib.get("output", "")} for s in port.findall("script")]
            item["ports"].append({"port": int(port.attrib.get("portid", "0")), "protocol": port.attrib.get("protocol", "unknown"),
                "state": state.attrib.get("state", "unknown") if state is not None else "unknown",
                "service": service.attrib.get("name", "unknown") if service is not None else "unknown",
                "product": service.attrib.get("product", "") if service is not None else "",
                "version": service.attrib.get("version", "") if service is not None else "", "scripts": scripts})
        data["hosts"].append(item)
    return data

def render_markdown(data):
    lines = ["# Network Security Assessment", "", "> Generated from Nmap XML. Review observations before assigning severity.", "",
        "## Scan metadata", "", "- **Generated (UTC):** " + data["generated_at_utc"],
        "- **Nmap version:** " + data["nmap_version"], "- **Command:** " + (data["scan_args"] or "not recorded"),
        "- **Input:** " + data["source_file"], "- **Hosts represented:** " + str(len(data["hosts"])), "", "## Host observations", ""]
    for i, host in enumerate(data["hosts"], 1):
        addresses = ", ".join(a["address"] for a in host["addresses"]) or "unknown"
        names = ", ".join(n for n in host["hostnames"] if n) or "none recorded"
        lines += ["### Host " + str(i) + ": " + addresses, "", "- **Status:** " + host["status"], "- **Hostnames:** " + names, ""]
        if not host["ports"]:
            lines += ["No port records present in XML.", ""]
        else:
            lines += ["| Port | State | Service | Product / version |", "|---|---|---|---|"]
            for p in host["ports"]:
                version = " ".join(x for x in (p["product"], p["version"]) if x) or "not identified"
                lines.append("| {}/{} | {} | {} | {} |".format(p["port"], p["protocol"], p["state"], p["service"], version))
            lines.append("")
        for p in host["ports"]:
            for script in p["scripts"]:
                lines += ["#### NSE output: " + script["id"] + " on " + str(p["port"]) + "/" + p["protocol"], "",
                          "Output: " + (script["output"] or "(No output recorded)"), ""]
    lines += ["## Analyst review", "", "For each observation, record impact, evidence, confidence, severity, remediation, owner, and retest status.",
              "Do not treat a banner or missing header as a confirmed vulnerability without context.", "", "## Scope and authorization", "",
              "Document approved targets, authorization, scan window, exclusions, and rate limits.", ""]
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("xml_file", type=Path, help="Nmap XML file produced with -oX")
    ap.add_argument("--markdown", type=Path, default=Path("assessment.md"))
    ap.add_argument("--json", dest="json_file", type=Path, default=Path("assessment.json"))
    args = ap.parse_args()
    if not args.xml_file.is_file(): ap.error("XML input does not exist: " + str(args.xml_file))
    data = parse_xml(args.xml_file)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json_file.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text(render_markdown(data), encoding="utf-8")
    args.json_file.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Wrote Markdown report: " + str(args.markdown))
    print("Wrote JSON report: " + str(args.json_file))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
