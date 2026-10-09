#!/usr/bin/env python3
"""Match installed package versions to public CVEs and write a triage report.

Lookup is NVD + CISA KEV. Wording is rule-based so it runs without an API key.
No reproduction steps are generated.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PACKAGES = ROOT / "packages.txt"
KEV_PATH = ROOT / "kev.json"
OUT = ROOT / "out"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = "cve-triage/0.1"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def load_packages():
    if not PACKAGES.exists():
        return []
    rows = []
    for line in PACKAGES.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host, package, version = "app-01", line, ""
        parts = line.split()
        if len(parts) >= 3:
            host, package, version = parts[0], parts[1], parts[2]
        elif len(parts) >= 2:
            package, version = parts[0], parts[1]
        else:
            continue
        rows.append({"host": host, "package": package, "version": version})
    return rows


NAMES = {
    "nginx": "nginx",
    "apache httpd": "apache",
    "httpd": "apache",
    "openssh": "openssh",
    "openssl": "openssl",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "microsoft iis": "iis",
}


def version_of(service):
    parts = (service.get("version") or "").strip().split()
    if not parts:
        return ""
    return parts[0].rstrip(",")


def packages_from_nmap(path):
    tree = ET.parse(path)
    lines = ["# from nmap -sV. banner version only."]
    seen = set()
    for host in tree.findall("host"):
        name = host.find("./hostnames/hostname")
        addr = host.find("./address")
        label = name.get("name") if name is not None and name.get("name") else (addr.get("addr") if addr is not None else "host")
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is not None and state.get("state") != "open":
                continue
            service = port.find("service")
            if service is None:
                continue
            raw = (service.get("product") or service.get("name") or "").lower()
            product = NAMES.get(raw, raw.split()[0] if raw else "")
            version = version_of(service)
            if not product or not version or version in {"unknown", "?"}:
                continue
            row = f"{label} {product} {version}"
            if row in seen:
                continue
            seen.add(row)
            lines.append(row)
    PACKAGES.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return load_packages()


def ensure_kev():
    if KEV_PATH.exists() and KEV_PATH.stat().st_size > 1000:
        data = json.loads(KEV_PATH.read_text())
    else:
        data = json.loads(fetch(KEV_URL))
        KEV_PATH.write_text(json.dumps(data))
    return {v["cveID"]: v for v in data["vulnerabilities"]}


CPE = {
    "nginx": ["a:f5:nginx", "a:nginx:nginx"],
    "openssl": ["a:openssl:openssl"],
    "sudo": ["a:sudo_project:sudo", "a:sudo:sudo"],
}


def nvd_search(package, version):
    vendors = CPE.get(package.lower(), [f"a:*:{package.lower()}"])
    queries = [(f"cpe:2.3:{vendor}:{version}:*:*:*:*:*:*:*", "cpe") for vendor in vendors]
    queries.append((package, "keyword"))
    last = {}
    for index, (value, how) in enumerate(queries):
        if index:
            time.sleep(6)
        params = {"resultsPerPage": 20}
        if how == "cpe":
            params["virtualMatchString"] = value
        else:
            params["keywordSearch"] = value
        try:
            data = json.loads(fetch(f"{NVD}?{urllib.parse.urlencode(params)}"))
        except Exception as exc:
            print(f"NVD lookup failed ({how}): {exc}")
            continue
        last = data
        total = data.get("totalResults")
        if total:
            return total, data.get("vulnerabilities", []), how
        if "totalResults" not in data:
            print(f"NVD response missing totalResults ({how}): {str(data)[:180]}")
    return last.get("totalResults", 0), last.get("vulnerabilities", []), "keyword"


def ver_tuple(value):
    nums = re.findall(r"\d+", value or "")
    return tuple(int(n) for n in nums) if nums else None


def in_range(installed, match):
    got = ver_tuple(installed)
    if not got:
        return None
    start = match.get("versionStartIncluding")
    start_ex = match.get("versionStartExcluding")
    end = match.get("versionEndExcluding")
    end_in = match.get("versionEndIncluding")
    exact = None
    criteria = match.get("criteria", "")
    parts = criteria.split(":")
    if len(parts) > 5 and parts[5] not in ("*", "-"):
        exact = parts[5]
    if not any((start, start_ex, end, end_in, exact)):
        return None
    if exact and ver_tuple(exact) != got:
        return False
    if start and got < ver_tuple(start):
        return False
    if start_ex and got <= ver_tuple(start_ex):
        return False
    if end and got >= ver_tuple(end):
        return False
    if end_in and got > ver_tuple(end_in):
        return False
    return True


def product_matches(package, match):
    criteria = match.get("criteria", "").lower()
    name = package.lower().split(":")[-1]
    return f":{name}:" in criteria or criteria.endswith(f":{name}")


def affected_range(matches):
    bits = []
    for match in matches:
        start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
        end = match.get("versionEndExcluding") or match.get("versionEndIncluding")
        if start or end:
            bits.append(f"{start or '*'} ~ {end or '*'}")
    return ", ".join(bits[:4]) or "version bound not in CPE"


def english_desc(cve):
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "")
    return ""


def cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            data = rows[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity") or rows[0].get("baseSeverity")
    return None, None


def cpe_matches(cve):
    found = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            found.extend(node.get("cpeMatch", []))
    return found


def classify(package, version, cve, kev):
    matches = [m for m in cpe_matches(cve) if m.get("vulnerable") and product_matches(package, m)]
    if not matches:
        return None
    hits = [in_range(version, m) for m in matches]
    if any(hit is True for hit in hits):
        status = "possible"
    elif hits and all(hit is False for hit in hits):
        status = "not applicable"
    else:
        status = "needs review"
    score, severity = cvss(cve)
    cve_id = cve["id"]
    kev_row = kev.get(cve_id)
    priority = "excluded"
    if status == "not applicable":
        priority = "excluded"
    elif kev_row:
        priority = "P1"
    elif score and score >= 7:
        priority = "P2"
    elif status == "possible":
        priority = "P3"
    return {
        "id": cve_id,
        "status": status,
        "priority": priority,
        "score": score,
        "severity": severity,
        "kev": bool(kev_row),
        "kev_name": (kev_row or {}).get("vulnerabilityName", ""),
        "range": affected_range(matches),
        "summary": english_desc(cve)[:180],
    }


TEAMS = {
    "nginx": "Web",
    "apache": "Web",
    "httpd": "Web",
    "iis": "Web",
    "openssh": "OS",
    "openssl": "OS",
    "sudo": "OS",
    "mysql": "DB",
    "mariadb": "DB",
    "postgresql": "DB",
    "microsoft": "Identity/AD",
}


def team_for(package):
    return TEAMS.get(package.lower(), "Infrastructure")


def ticket_body(row, item):
    kev = "Listed in CISA KEV. Public exploitation has been reported." if item["kev"] else "Not in KEV. CVSS alone is not enough for P1."
    lines = [
        f"Target: {row['host']} / {row['package']} {row['version']}",
        f"CVE: {item['id']} / CVSS {item['score']} {item['severity'] or ''}".rstrip(),
        f"Status: {item['status']}. Affected range {item['range']}. Installed version overlaps the range, so {item['priority']}.",
        kev,
        f"Owner: {team_for(row['package'])}. Do not confirm remediation before rechecking the package version and enabled modules.",
        "Request: recheck the version, then update or mitigate. No reproduction steps.",
    ]
    return lines


def write_outputs(rows):
    OUT.mkdir(exist_ok=True)
    report = ["# CVE triage draft", "", "Final judgment is empty. Do not treat this as confirmed before the version is rechecked.", ""]
    tickets = ["# Ticket draft", ""]
    for row in rows:
        report.append(f"## {row['host']} / {row['package']} {row['version']}")
        report.append(f"- NVD results: {row['total']} ({row['how']})")
        if not row["findings"]:
            report.append("- No overlapping CVE in the top 20 results")
            report.append("")
            continue
        for item in row["findings"]:
            report.append(
                f"- {item['id']} | CVSS {item['score']} {item['severity'] or ''} | "
                f"KEV {'yes' if item['kev'] else 'no'} | {item['status']} | {item['priority']}"
            )
            report.append(f"  - Affected range: {item['range']}")
            report.append("  - Final judgment: unverified")
            if item["priority"] == "P1":
                tickets.append(f"## [P1] {row['host']} {row['package']} {row['version']} update")
            elif item["status"] == "possible":
                tickets.append(f"## [{item['priority']}] {row['host']} {row['package']} {row['version']} review")
            else:
                continue
            tickets.extend(f"- {line}" for line in ticket_body(row, item))
            tickets.append("")
        report.append("")
    (OUT / "report.md").write_text("\n".join(report) + "\n")
    if len(tickets) == 2:
        tickets.append("No ticket items for this input.")
    (OUT / "tickets.md").write_text("\n".join(tickets) + "\n")
    ai = [
        "Group CVEs for the same package into one ticket.",
        "Write KEV items first. CVSS items that are not in KEV should be review tickets.",
        "If the affected range starts with * or the patch level is missing, mark it as a possible false positive.",
        "Output tickets only. Do not repeat the instructions, reasoning, or a preamble.",
        "",
    ]
    sent = 0
    for row in rows:
        kept = 0
        for item in row["findings"]:
            if item["status"] == "not applicable":
                continue
            if item["priority"] not in {"P1", "P2"}:
                continue
            if item["priority"] == "P2" and kept >= 2:
                continue
            wide = item["range"].startswith("*") or "p" in row["version"]
            ai.append(f"host: {row['host']}")
            ai.append(f"package: {row['package']} {row['version']}")
            ai.append(f"cve: {item['id']}")
            ai.append(f"cvss: {item['score']}")
            ai.append(f"kev: {str(item['kev']).lower()}")
            ai.append(f"affected_range: {item['range']}")
            ai.append(f"priority: {item['priority']}")
            ai.append(f"team: {team_for(row['package'])}")
            ai.append(f"false_positive_risk: {'high' if wide else 'low'}")
            ai.append("")
            kept += 1
            sent += 1
    if sent == 0:
        ai.append("No items to send")
    (OUT / "ai_input.md").write_text("\n".join(ai) + "\n")


def main():
    args = sys.argv[1:]
    if args[:1] == ["--scan"]:
        if len(args) < 2:
            print("usage: python3 triage.py --scan 10.10.10.10")
            return 1
        OUT.mkdir(exist_ok=True)
        xml_path = OUT / "nmap.xml"
        subprocess.run(["nmap", "-sV", "-oX", str(xml_path), args[1]], check=True)
        packages = packages_from_nmap(xml_path)
    elif args[:1] == ["--nmap"]:
        if len(args) < 2:
            print("usage: python3 triage.py --nmap scan.xml")
            return 1
        packages = packages_from_nmap(args[1])
    elif not args:
        packages = load_packages()
    else:
        print("usage: python3 triage.py")
        print("       python3 triage.py --nmap scan.xml")
        print("       python3 triage.py --scan 10.10.10.10")
        return 1
    if not packages:
        print("no versions to check")
        return 1
    kev = ensure_kev()
    rows = []
    for index, pkg in enumerate(packages):
        if index:
            time.sleep(6)
        total, vulns, how = nvd_search(pkg["package"], pkg["version"])
        findings = []
        excluded = []
        for wrapper in vulns:
            item = classify(pkg["package"], pkg["version"], wrapper["cve"], kev)
            if not item:
                continue
            if item["status"] == "not applicable":
                excluded.append(item)
            else:
                findings.append(item)
        findings.sort(key=lambda item: ({"P1": 0, "P2": 1, "P3": 2}.get(item["priority"], 9), -(item["score"] or 0)))
        if not findings and excluded:
            findings = excluded[:1]
        rows.append({**pkg, "total": total, "how": how, "findings": findings[:5]})
        print(f"{pkg['package']} {pkg['version']}: {how} {total}, kept {len(findings[:5])}")
    write_outputs(rows)
    print(f"wrote {OUT / 'report.md'}")
    print(f"wrote {OUT / 'tickets.md'}")
    print(f"wrote {OUT / 'ai_input.md'}")
    if os.environ.get("XAI_API_KEY"):
        subprocess.run([sys.executable, str(ROOT / "grok_ticket.py")], check=False)
    else:
        print("XAI_API_KEY is not set. Skipping grok_ticket.py")
    subprocess.run([sys.executable, str(ROOT / "report_pdf.py")], check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
