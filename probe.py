#!/usr/bin/env python3
"""Probe harness for Intigriti Challenge 0926 (Critter Gallery).
Reads RAW SQL payload lines from stdin, base64-encodes (as the app expects),
URL-encodes, fetches, and prints HTTP status + parsed detail section.
"""
import utils.session
import base64
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://challenge-0926.challenges.intigriti.io/challenge.php"
UA = "Mozilla/5.0 (compatible; curl/8.0)"


def fetch(pic_b64: str):
    url = BASE + "?pic=" + urllib.parse.quote(pic_b64, safe="")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, "ERR %s" % e


def detail(body: str) -> str:
    m = re.search(r'<section class="detail">(.*?)</section>', body, re.S)
    if not m:
        return "[no detail section]"
    seg = m.group(1)
    art = re.search(r'class="art">(.*?)</div>', seg, re.S)
    h2 = re.search(r"<h2>(.*?)</h2>", seg, re.S)
    desc = re.search(r'class="(desc[^"]*)">(.*?)</div>', seg, re.S)
    return "art=%r h2=%r desc[%s]=%r" % (
        art.group(1) if art else None,
        h2.group(1) if h2 else None,
        desc.group(1) if desc else "ABSENT",
        desc.group(2) if desc else None,
    )


ERRWORDS = (
    "sql syntax",
    "fatal error",
    "warning:",
    "mysqli",
    "pdoexception",
    "unknown column",
    "uncaught",
)


def show(raw: str, verbose: bool = False) -> None:
    b64 = base64.b64encode(raw.encode()).decode()
    st, body = fetch(b64)
    print("RAW  : %r" % raw)
    print("B64  : %s" % b64)
    print("HTTP : %s LEN=%s bytes" % (st, len(body.encode("utf-8"))))
    print("DET  : %s" % detail(body))
    low = body.lower()
    for kw in ERRWORDS:
        if kw in low:
            i = low.index(kw)
            print("ERR? : ...%s..." % body[max(0, i - 150):i + 250].replace("\n", " "))
    if verbose:
        print(body)
    print("-" * 72)


if __name__ == "__main__":
    for line in sys.stdin:
        line = line.rstrip("\n")
        if line == "":
            continue
        show(line)
