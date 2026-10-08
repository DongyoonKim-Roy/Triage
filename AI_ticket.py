#!/usr/bin/env python3
"""Send out/ai_input.md to the xAI API and save the ticket text."""

import json
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROMPT = ROOT / "out" / "ai_input.md"
DEST = ROOT / "out" / "tickets_ai.md"
URL = "https://api.x.ai/v1/responses"
MODEL = os.environ.get("XAI_MODEL", "grok-4.6")


def response_text(data):
    if data.get("output_text"):
        return data["output_text"]
    parts = []
    for item in data.get("output") or []:
        if item.get("type") not in {None, "message"}:
            continue
        for block in item.get("content") or []:
            if block.get("type") not in {None, "output_text"}:
                continue
            if block.get("text"):
                parts.append(block["text"])
    return "\n".join(parts).strip()


def main():
    key = os.environ.get("XAI_API_KEY", "")
    if not key:
        print("XAI_API_KEY is not set")
        return 1
    if not PROMPT.exists():
        print(f"missing {PROMPT}")
        return 1
    prompt = PROMPT.read_text(encoding="utf-8")
    prompt = "Output tickets only. Do not repeat the instructions, reasoning, or a preamble.\n\n" + prompt
    payload = json.dumps({
        "model": MODEL,
        "input": prompt,
    }).encode()
    req = urllib.request.Request(
        URL,
        data=payload,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    text = response_text(data)
    if not text:
        raw = ROOT / "out" / "grok_raw.json"
        raw.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"no text in response, wrote {raw}")
        return 1
    DEST.write_text(text + "\n", encoding="utf-8")
    print(f"wrote {DEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
