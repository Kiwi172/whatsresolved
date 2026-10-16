# whatsresolved

[![tests](https://github.com/Kiwi172/whatsresolved/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiwi172/whatsresolved/actions/workflows/ci.yml)

**Watch the DNS records your hosts actually have — and notice when they
change.**

Your recon lists are static; DNS is not. A new `TXT` verification record
means someone wired up a SaaS tool this week (and an unclaimed CNAME to
it is a takeover candidate). A `CNAME` appearing where there was an `A`
means the host moved behind a CDN. IPs changing means infrastructure
moved. `dig` answers once and forgets. `whatsresolved` keeps a local
history and answers the question that matters on the next run:
**what changed?**

```
   run 1                          run 2 (two weeks later)
   ┌──────────────────┐          ┌─────────────────────────────────┐
   │ app.example.com  │  local   │ app.example.com                 │
   │ TXT: (none)      │  JSON    │ CHANGED since last run:         │
   │ A:   10.0.0.5    │ history ▶│   TXT + atlassian-domain-...    │
   │ BASELINE         │          │     ^ SaaS wired up here; check │
   └──────────────────┘          │       for subdomain takeover    │
                                 │   A   - 10.0.0.5  / + 10.0.0.9  │
                                 │     ^ IP moved                  │
                                 └─────────────────────────────────┘
```

It carries its **own DNS client**: the Python standard library has no
way to ask for a `TXT` or `CNAME` record at all (only `getaddrinfo`,
which flattens everything to addresses). whatsresolved builds query
packets and parses responses — including name-compression pointers —
over UDP, straight from `socket` + `struct`. No dnspython, no services,
no accounts. The history is a plain JSON file you own.

---

## Install

Any machine with Python 3.9 or newer:

```bash
curl -sO https://raw.githubusercontent.com/Kiwi172/whatsresolved/main/whatsresolved.py
chmod +x whatsresolved.py
```

Or:

```bash
pipx install git+https://github.com/Kiwi172/whatsresolved
```

## Use

One host, or the recon list you already have:

```bash
whatsresolved app.example.com api.example.com
whatsresolved --file in-scope-hosts.txt            # one host per line
whatsresolved --file hosts.txt --types A,CNAME,TXT # only what you care about
whatsresolved --history                            # the stored timeline
whatsresolved app.example.com --json | jq '.results[].changes'
```

It uses your system resolver (first `nameserver` from `/etc/resolv.conf`)
or any resolver you name:

```bash
whatsresolved example.com --server 1.1.1.1
```

Sample output:

```
app.example.com
  A      1     10.0.0.5
  AAAA   0
  CNAME  1     dualstack.lb.example.com
  MX     0
  TXT    1     atlassian-domain-verify=abc
  unchanged
```

## What it flags, and what it refuses to claim

| observation | meaning attached |
|---|---|
| new `TXT` matching verification patterns | "SaaS wired up here — check for subdomain takeover" |
| new `CNAME` to a takeover-prone endpoint (github.io, herokuapp, netlify, S3, statuspage, …) | takeover candidate |
| `A`/`AAAA` added or removed | IP moved — infrastructure change |
| `NXDOMAIN` | the name is gone (recorded as a state, not an error) |

And the honesty rule: **a timeout is `INCONCLUSIVE`, never "record
removed."** A resolver hiccup must not look like your attack surface
shrank. Identical repeats update `last_seen` instead of growing the
history (capped at 50 distinct observations per host).

## Non-goals

- **Not a resolver library.** It answers six record types over UDP; for
  DNSSEC, SRV, or dynamic updates, use a real library.
- **Not a takeover scanner.** It points at takeover candidates;
  confirming one means fetching the target — your usual tools do that.
- **Not a monitor daemon.** Cron it daily; it keeps state between runs.

## Tests

```bash
python3 -m pytest tests/      # or: python3 tests/test_whatsresolved.py
```

The wire format is tested against hand-built DNS packets (A, TXT, MX,
and a CNAME chain using compression pointers), and the full
baseline → unchanged → changed lifecycle runs against a local UDP DNS
server — no internet, no dependency on any resolver's behaviour.

## License

MIT
