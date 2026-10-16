#!/usr/bin/env python3
"""whatsresolved -- watch the DNS records your hosts actually have.

You have lists of subdomains from recon. Static lists go stale: names
get new CNAMEs, TXT verifications appear when a team wires up a SaaS
(usually a takeover candidate a week later), IPs move, names expire.
`dig` answers once; nothing remembers.

whatsresolved carries its own tiny DNS client (the Python standard
library has none beyond getaddrinfo): it queries A, AAAA, CNAME, MX,
TXT and NS over UDP, keeps a local JSON history per host, and diffs
run against run -- added/removed records per type, with interpretation
for the ones that matter. A timeout is reported as inconclusive, never
as "record removed".

Stdlib-only. No dnspython, no services, history is a file you own.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
MAX_OBS = 50

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in TYPES.items()}

# CNAME targets that are classic subdomain-takeover candidates
TAKEOVER_ENDPOINTS = (
    "github.io", "gitlab.io", "herokuapp.com", "herokudns.com",
    "netlify.app", "netlify.com", "azurewebsites.net", "cloudapp.net",
    "web.app", "firebaseapp.com", "s3.amazonaws.com", "s3-website",
    "statuspage.io", "freshdesk.com", "zendesk.com", "helpscout.net",
    "unbouncepages.com", "readme.io", "fastly", "bitbucket.io",
    "surge.sh", "ngrok.io", "tumblr.com", "wishpond.com",
)
VERIFICATION_TXT = re.compile(
    r"(?i)(verify|verification|atlassian|google-site|apple-domain|"
    r"dh=|key=|zoho|mailchimp|sendgrid|spf|dkim|recorded|managemydns|"
    r"okta|atlassian-domain|adobe-idp|cisco|onetrust|trustwave)")


# ---------------------------------------------------------------------------
# tiny DNS/UDP client
# ---------------------------------------------------------------------------

def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError:
            raw = label.encode("idna")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name, rtype, rd=True):
    tid = random.randrange(1 << 16)
    flags = 0x0100 if rd else 0
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    q = encode_name(name) + struct.pack(">HH", rtype, 1)
    return tid, header + q


def decode_name(data, off, depth=0):
    """Return (name, new_offset). Follows compression pointers."""
    labels, jumps = [], 0
    while True:
        if off >= len(data):
            raise ValueError("name runs off the packet")
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if jumps > 10:
                raise ValueError("compression loop")
            jumps += 1
            if depth > 10:
                raise ValueError("compression too deep")
            rest, _ = decode_name(data, ptr, depth + 1)
            labels.extend(rest.split("."))
            off += 2
            break
        labels.append(data[off + 1:off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(labels), off


def parse_response(raw, want_id):
    """Return (rcode, {TYPE: [values]}) or raise ValueError."""
    if len(raw) < 12:
        raise ValueError("short packet")
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", raw[:12])
    if tid != want_id:
        raise ValueError("id mismatch")
    rcode = flags & 0xF
    off = 12
    for _ in range(qd):                       # skip questions
        _, off = decode_name(raw, off)
        off += 4
    records = {}
    for _ in range(an + ns + ar):
        if off >= len(raw):
            break
        _, off = decode_name(raw, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", raw[off:off + 10])
        off += 10
        rdata = raw[off:off + rdlen]
        off += rdlen
        tname = TYPE_NAMES.get(rtype)
        if tname is None or rclass != 1:
            continue
        if tname == "A":
            val = socket.inet_ntop(socket.AF_INET, rdata)
        elif tname == "AAAA":
            val = socket.inet_ntop(socket.AF_INET6, rdata)
        elif tname in ("CNAME", "NS"):
            val, _ = decode_name(raw, off - rdlen)
        elif tname == "MX":
            pref = struct.unpack(">H", rdata[:2])[0]
            host, _ = decode_name(raw, off - rdlen + 2)
            val = f"{pref} {host}"
        elif tname == "TXT":
            parts, p = [], 0
            while p < len(rdata):
                ln = rdata[p]
                parts.append(rdata[p + 1:p + 1 + ln].decode("utf-8", "replace"))
                p += 1 + ln
            val = "".join(parts)
        else:
            continue
        records.setdefault(tname, []).append(val)
    return rcode, {k: sorted(v) for k, v in records.items()}


def system_resolver():
    try:
        for line in open("/etc/resolv.conf"):
            m = re.match(r"\s*nameserver\s+(\S+)", line)
            if m:
                return m.group(1)
    except OSError:
        pass
    return "127.0.0.0"  # will fail loudly if nothing local


def query(host, rtype, server, timeout, retries=2, port=53):
    tid, packet = build_query(host, TYPES[rtype])
    last_err = None
    for _ in range(retries + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(packet, (server, port))
            raw, _ = s.recvfrom(65535)
            s.close()
            return parse_response(raw, tid)
        except Exception as e:
            last_err = e
    raise last_err


# ---------------------------------------------------------------------------
# state + diffing
# ---------------------------------------------------------------------------

def load_state(path):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"tool": "whatsresolved", "version": VERSION, "hosts": {}}


def diff_records(prev, cur):
    """(changes, hints) between two record dicts."""
    changes, hints = [], []
    for t in sorted(set(prev) | set(cur)):
        a, b = set(prev.get(t, [])), set(cur.get(t, []))
        for v in sorted(b - a):
            changes.append(f"{t} + {v}")
            if t == "TXT" and VERIFICATION_TXT.search(v):
                hints.append(f"new verification TXT -> SaaS wired up here; "
                             f"check for subdomain takeover")
            if t == "CNAME" and any(v.lower().endswith(e) or f".{e}" in v.lower()
                                    for e in TAKEOVER_ENDPOINTS):
                hints.append(f"CNAME to a takeover-prone endpoint ({v})")
            if t in ("A", "AAAA"):
                hints.append("IP moved -- infrastructure change")
        for v in sorted(a - b):
            changes.append(f"{t} - {v}")
    return changes, hints


def record(state, host, recs, rcode):
    entry = state["hosts"].setdefault(host, {"observations": []})
    obs = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "records": recs, "rcode": rcode}
    obslist = entry["observations"]
    if obslist and obslist[-1]["records"] == recs:
        obslist[-1]["last_seen"] = obs["ts"]
        return "unchanged", None
    prev = obslist[-1] if obslist else None
    obslist.append(obs)
    entry["observations"] = obslist[-MAX_OBS:]
    return ("changed" if prev else "baseline"), prev


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(
        prog="whatsresolved",
        description="Watch DNS records (A, AAAA, CNAME, MX, TXT, NS) over "
                    "time with a local history. Built-in stdlib DNS "
                    "client; no dnspython, no services.")
    ap.add_argument("hosts", nargs="*", metavar="HOST",
                    help="hostnames to query (or use --file)")
    ap.add_argument("--file", metavar="PATH", help="one host per line")
    ap.add_argument("--types", default="A,AAAA,CNAME,MX,TXT",
                    help="comma list: A,AAAA,CNAME,MX,TXT,NS "
                         "(default: A,AAAA,CNAME,MX,TXT)")
    ap.add_argument("--server", metavar="IP",
                    help="resolver IP (default: first from /etc/resolv.conf)")
    ap.add_argument("--port", type=int, default=53,
                    help="resolver port (default: 53)")
    ap.add_argument("--state", metavar="PATH", default="whatsresolved.json")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--delay", type=float, default=0.1,
                    help="seconds between hosts (default: 0.1)")
    ap.add_argument("--history", action="store_true",
                    help="print the stored timeline instead of querying")
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--version", action="version",
                    version=f"whatsresolved {VERSION}")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    types = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    bad = [t for t in types if t not in TYPES]
    if bad:
        print(f"whatsresolved: unknown type(s): {','.join(bad)}",
              file=sys.stderr)
        return 2
    server = args.server or system_resolver()

    state_path = Path(args.state)
    state = load_state(state_path)

    hosts = list(args.hosts)
    if args.file:
        hosts += [l.strip() for l in Path(args.file).read_text(errors="replace")
                  .splitlines() if l.strip() and not l.startswith("#")]
    hosts = [re.sub(r"^[a-z]+://", "", h).split("/")[0] for h in hosts]

    if args.history:
        print(json.dumps(state["hosts"], indent=1))
        return 0
    if not hosts:
        print("whatsresolved: no hosts given", file=sys.stderr)
        return 2

    emit = (lambda *a: None) if args.as_json else print
    results = []
    for host in hosts:
        recs, rcode, err = {}, 0, None
        for t in types:
            try:
                rc, got = query(host, t, server, args.timeout,
                                port=args.port)
                if rc == 3:
                    rcode = 3
                elif rcode == 0:
                    rcode = rc
                recs[t] = got.get(t, [])
            except Exception as e:
                err = str(e)
        if err and not recs:
            emit(f"{host}: {c('33', 'INCONCLUSIVE')} (DNS error: {err})")
            results.append({"host": host, "status": "inconclusive",
                            "error": err})
            continue
        status, prev = record(state, host, recs, rcode)
        changes, hints = ([], [])
        if status == "changed" and prev:
            changes, hints = diff_records(prev["records"], recs)

        emit(host + ("  " + c("33", "(NXDOMAIN)") if rcode == 3 else ""))
        for t in types:
            vals = recs.get(t, [])
            emit(f"  {t:<6} {len(vals)}  " + (vals[0][:60] if vals else ""))
        if status == "baseline":
            emit("  " + c("36", "BASELINE") + " recorded")
        elif status == "unchanged":
            emit("  " + c("32", "unchanged"))
        else:
            emit("  " + c("31", "CHANGED since last run:"))
            for ch in changes:
                emit(c("90", f"    {ch}"))
            for h in hints:
                emit(c("35", f"    ^ {h}"))
        results.append({"host": host, "status": status, "rcode": rcode,
                        "records": recs, "changes": changes, "hints": hints})
        if args.delay:
            time.sleep(args.delay)

    state_path.write_text(json.dumps(state, indent=1))
    if args.as_json:
        print(json.dumps({"tool": "whatsresolved", "version": VERSION,
                          "resolver": server, "results": results}, indent=1))
    else:
        changed = sum(1 for r in results if r["status"] == "changed")
        print(f"{len(hosts)} host(s) queried via {server} · {changed} "
              f"record change(s) · history: {state_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
