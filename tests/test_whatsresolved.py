"""Tests for whatsresolved. Run with: python3 -m pytest tests/ (or python3 tests/test_whatsresolved.py)

The wire format is tested against hand-built packets (including
compression pointers), and the watch/diff lifecycle against a local UDP
DNS server -- no internet, no resolver dependency.
"""
from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

TOOL = str(Path(__file__).resolve().parent.parent / "whatsresolved.py")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import whatsresolved as wr  # noqa: E402


def run(*argv):
    return subprocess.run([sys.executable, TOOL, *argv],
                          capture_output=True, text=True)


# ---------------------------------------------------------------------------
# wire format: hand-built packets
# ---------------------------------------------------------------------------

def qsection(name, rtype):
    return (b"".join(bytes([len(l)]) + l.encode() for l in name.split("."))
            + b"\x00" + struct.pack(">HH", rtype, 1))


def header(tid, an, rcode=0):
    return struct.pack(">HHHHHH", tid, 0x8180 | rcode, 1, an, 0, 0)


def test_encode_and_query_shape():
    tid, pkt = wr.build_query("a.test", 1)
    assert pkt[:4] == struct.pack(">HH", tid, 0x0100)
    assert pkt[12:] == b"\x01a\x04test\x00" + struct.pack(">HH", 1, 1)


def test_parse_a_record():
    q = qsection("a.test", 1)
    ans = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
           + socket.inet_aton("93.184.216.34"))
    raw = header(7, 1) + q + ans
    rcode, recs = wr.parse_response(raw, 7)
    assert rcode == 0 and recs == {"A": ["93.184.216.34"]}


def test_parse_txt_and_mx():
    q = qsection("m.test", 16)
    txt = b"\x0bhello=world"
    ans1 = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(txt)) + txt
    mxval = struct.pack(">H", 10) + b"\x04mail\x04test\x00"
    ans2 = (b"\xc0\x0c" + struct.pack(">HHIH", 15, 1, 60, len(mxval))
            + mxval)
    raw = header(9, 2) + q + ans1 + ans2
    _, recs = wr.parse_response(raw, 9)
    assert recs["TXT"] == ["hello=world"]
    assert recs["MX"] == ["10 mail.test"]


def test_parse_cname_compression_chain():
    q = qsection("w.test", 5)
    # rdata: full name "target.test" then a second CNAME using a pointer
    full = b"\x06target\x04test\x00"
    ans1 = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(full)) + full
    ptr = b"\xc0\x24"                       # points at "target.test" above
    ans2 = (b"\x02w2\xc0\x0c"
            + struct.pack(">HHIH", 5, 1, 60, len(ptr)) + ptr)
    raw = header(11, 2) + q + ans1 + ans2
    _, recs = wr.parse_response(raw, 11)
    assert recs["CNAME"] == sorted(["target.test", "target.test"])


def test_nxdomain_and_id_mismatch():
    q = qsection("x.test", 1)
    raw = header(5, 0, rcode=3) + q
    assert wr.parse_response(raw, 5)[0] == 3
    try:
        wr.parse_response(raw, 6)
        assert False
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# local UDP DNS server for the watch lifecycle
# ---------------------------------------------------------------------------

STATE = {"txt": [b"\x1batlassian-domain-verify=abc"]}


def dns_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                data, addr = srv.recvfrom(65535)
            except OSError:
                return
            tid = struct.unpack(">H", data[:2])[0]
            # find qtype: name ends at \x00 then 2 bytes type
            i = 12
            while data[i] != 0:
                i += 1
            qtype = struct.unpack(">H", data[i + 1:i + 3])[0]
            q = data[12:i + 5]
            ans = b""
            an = 0
            if qtype == 16:                      # TXT
                for t in STATE["txt"]:
                    ans += (b"\xc0\x0c"
                            + struct.pack(">HHIH", 16, 1, 60, len(t)) + t)
                    an += 1
            elif qtype in (1, 28, 5, 15):        # empty NOERROR for others
                pass
            else:
                ans = b""
            srv.sendto(header(tid, an) + q + ans, addr)

    threading.Thread(target=loop, daemon=True).start()
    return srv, port


def test_cli_lifecycle(tmp_path):
    srv, port = dns_server()
    state = str(tmp_path / "s.json")
    common = ["a.test", "--types", "TXT", "--server", "127.0.0.1",
              "--port", str(port), "--state", state, "--delay", "0"]
    r1 = run(*common)
    assert "BASELINE" in r1.stdout
    assert "atlassian-domain-verify" in r1.stdout
    r2 = run(*common)
    assert "unchanged" in r2.stdout
    STATE["txt"] = [b"\x1batlassian-domain-verify=abc",
                    b"\x1bgoogle-site-verification=zz"]
    r3 = run(*common)
    assert "CHANGED" in r3.stdout
    assert "TXT + google-site-verification=zz" in r3.stdout
    assert "SaaS wired up" in r3.stdout
    srv.close()


def test_diff_hints():
    prev = {"CNAME": ["old.github.io"], "A": ["1.1.1.1"]}
    cur = {"CNAME": ["new.herokuapp.com"], "A": ["2.2.2.2"]}
    changes, hints = wr.diff_records(prev, cur)
    assert "CNAME + new.herokuapp.com" in changes
    assert "A - 1.1.1.1" in changes
    assert any("takeover" in h for h in hints)
    assert any("IP moved" in h for h in hints)


def test_history_flag(tmp_path):
    state = tmp_path / "s.json"
    state.write_text(json.dumps(
        {"hosts": {"a.test": {"observations": [{"ts": "x", "records": {}}]}}}))
    r = run("--history", "--state", str(state))
    d = json.loads(r.stdout)
    assert "a.test" in d


if __name__ == "__main__":
    import inspect
    import tempfile
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                if inspect.signature(fn).parameters:
                    with tempfile.TemporaryDirectory() as d:
                        STATE["txt"] = [b"\x1batlassian-domain-verify=abc"]
                        fn(Path(d))
                else:
                    fn()
                print(f"  ok  {name}")
            except Exception as e:
                failed += 1
                print(f"FAIL  {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
