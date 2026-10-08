# CVE triage

nmap service banners are matched to public CVEs and turned into owner-specific tickets. This is not a CVE research tool and it does not generate exploit steps.

Matching and priority are done in code. An LLM is used only to turn the filtered rows into ticket text. The CVE id and KEV flag are checked again by hand. A finding stays unverified until the banner version is compared with the installed package.

## What it does

- Read product and version from `nmap -sV`, or from `packages.txt`.
- Query NVD and compare the installed version with the CPE affected range. Versions outside the range are dropped.
- Mark CISA KEV items that overlap the range as P1. High CVSS without KEV stays a review ticket.
- Mark wide ranges and patch-level versions as higher false-positive risk.
- Route nginx and Apache to Web, OpenSSH and OpenSSL to OS, and database banners to DB.
- Ask the model to group CVEs for the same package into one ticket. No reproduction steps.
- Write a draft PDF with a count by owning team.

## Layout

```text
triage.py        lookup, version check, priority, team, report
grok_ticket.py   send out/ai_input.md to the xAI API
report_pdf.py    build out/triage.pdf
packages.txt     host package version, one per line
out/             report, tickets, PDF
```

## Run

```bash
export XAI_API_KEY='key from the console'
python3 triage.py --scan 10.0.0.1
```

`triage.py` writes `out/ai_input.md`, then calls `grok_ticket.py` and `report_pdf.py`. Without `XAI_API_KEY` it skips the API and still writes the rule-based report.

An existing package list does not need another scan.

```bash
python3 triage.py
```

PDF only:

```bash
pip3 install reportlab
python3 report_pdf.py
```

Korean text in the PDF needs a CJK font, for example `fonts-wqy-zenhei`.

## Input

```text
10.0.0.1 nginx 1.18.0
10.0.0.1 openssh 8.9p1
```

Only banner versions are read from nmap. A package that is not in the banner, such as OpenSSL on a host that only shows nginx, is not checked.

## Sample result

On a lab host, nginx 1.18.0 overlapped CVE-2023-44487, which is in CISA KEV, so it became a Web update ticket. OpenSSH 8.9p1 had high CVSS scores but no KEV entry, and the patch suffix made the false-positive risk high, so it stayed an OS review ticket. Neither was marked confirmed.

## Limits

- Nmap cannot see packages that do not appear in a service banner.
- Windows build numbers are not treated as package versions.
- The top NVD results can miss a CVE. A miss is not a clean bill of health.
- The model does not decide whether the host is vulnerable.

Do not commit `XAI_API_KEY`, `out/grok_raw.json`, or scan files from a network you do not own.
