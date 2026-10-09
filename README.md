

https://github.com/user-attachments/assets/68612c57-c702-4214-a582-89358b5407b2



# CVE triage

nmap service banners are matched to public CVEs and turned into owner-specific tickets. This is not a CVE research tool and it does not generate exploit steps.

Matching and priority are done in code. Ticket wording uses Grok through the xAI API, and only after the rows are filtered. Grok does not decide whether a host is vulnerable. The CVE id and KEV flag are checked again by hand. A finding stays unverified until the banner version is compared with the installed package.

## Grok

Ticket text is written by Grok. The script calls `https://api.x.ai/v1/responses` with `grok-4.6`. Another vendor key will not work without changing the request.

Grok receives the filtered rows and is told to group CVEs for the same package into one ticket. It is not asked for exploit steps, and it is not asked to confirm the finding. Set the key before running:

```bash
export XAI_API_KEY='key from console.x.ai'
export XAI_MODEL='grok-4.6'
```

The key is read from the environment. Do not put it in the script or the repo.

## What it does

- Read product and version from `nmap -sV`, or from `packages.txt`.
- Query NVD and compare the installed version with the CPE affected range. Versions outside the range are dropped.
- Mark CISA KEV items that overlap the range as P1. High CVSS without KEV stays a review ticket.
- Mark wide ranges and patch-level versions as higher false-positive risk.
- Route nginx and Apache to Web, OpenSSH and OpenSSL to OS, and database banners to DB.
- Send the filtered rows to Grok and ask it to group CVEs for the same package into one ticket. No reproduction steps.
- Write a draft PDF with a count by owning team.

## Layout

```text
triage.py        lookup, version check, priority, team, report
AI_ticket.py   send out/ai_input.md to Grok on the xAI API
report_pdf.py    build out/triage.pdf
packages.txt     host package version, one per line
out/             report, tickets, PDF
```

## Run

```bash
export XAI_API_KEY='key from console.x.ai'
export XAI_MODEL='grok-4.6'
python3 triage.py --scan 10.0.0.1
```

`triage.py` writes `out/ai_input.md`, then calls Grok through `grok_ticket.py`, then builds the PDF. Without `XAI_API_KEY` it skips Grok and still writes the rule-based report.

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
- Grok does not decide whether the host is vulnerable. It only writes the ticket text.

Do not commit `XAI_API_KEY`, `out/grok_raw.json`, or scan files from a network you do not own.

https://github.com/user-attachments/assets/6fb96280-adf2-49f6-bf17-845a009e00e4


