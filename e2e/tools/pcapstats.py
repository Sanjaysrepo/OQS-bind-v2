"""Summarise DNS transactions in a capture (via pcapdump.py output or a pcap).

Usage: pcapstats.py <file.pcap | pcapdump-output.txt> [--filter TYPE]

Groups datagrams by (client port, transaction id), prints one line per
transaction that used more than one datagram in a direction (i.e. was
fragmented) and totals: datagrams, bytes on the wire, wall time between the
first query and the last reply, and whether TCP was used.
"""
import re
import subprocess
import sys
import os
from collections import defaultdict

HDR = re.compile(r"^#(\d+) t=\+([\d.]+)s (UDP|TCP) ([\d.]+):(\d+) -> ([\d.]+):(\d+) udp/tcp payload=(\d+)B")
IDL = re.compile(r"^\s+id=0x([0-9a-f]+) qr=(\d) opcode=(\d+) .* tc=(\d) .* rcode=(\d+)")
QL = re.compile(r"^\s+Q: \('([^']*)', '?([^',]*)'?, \d+\)")
OPT = re.compile(r"'frag_nr': (\d+), 'nr_frags': (\d+)")


def load(path):
    if path.endswith(".pcap"):
        here = os.path.dirname(os.path.abspath(__file__))
        text = subprocess.run([sys.executable, os.path.join(here, "pcapdump.py"), path],
                              capture_output=True, text=True).stdout
    else:
        text = open(path, encoding="utf-8", errors="replace").read()
    pkts = []
    cur = None
    for line in text.splitlines():
        m = HDR.match(line)
        if m:
            cur = {"n": int(m[1]), "t": float(m[2]), "proto": m[3], "src": m[4], "sport": int(m[5]),
                   "dst": m[6], "dport": int(m[7]), "len": int(m[8]), "q": None, "frag": None}
            pkts.append(cur)
            continue
        if cur is None:
            continue
        m = IDL.match(line)
        if m:
            cur.update(id=m[1], qr=int(m[2]), opcode=int(m[3]), tc=int(m[4]), rcode=int(m[5]))
            continue
        m = QL.match(line)
        if m and cur["q"] is None:
            cur["q"] = f"{m[1]} {m[2]}"
        m = OPT.search(line)
        if m:
            cur["frag"] = (int(m[1]), int(m[2]))
    return pkts


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flt = None
    if "--filter" in sys.argv:
        flt = sys.argv[sys.argv.index("--filter") + 1]
    pkts = load(args[0])
    tx = defaultdict(list)
    for p in pkts:
        if "id" not in p:
            continue
        cport = p["sport"] if p["qr"] == 0 else p["dport"]
        server = p["dst"] if p["qr"] == 0 else p["src"]
        tx[(server, cport, p["id"])].append(p)

    print(f"{'query':40} {'proto':5} {'dgrams':>6} {'bytes':>7} {'frags':>5} {'ms':>7}  notes")
    tot = {"tx": 0, "dgrams": 0, "bytes": 0, "frag_tx": 0, "tcp_tx": 0}
    for key, ps in sorted(tx.items(), key=lambda kv: kv[1][0]["t"]):
        q = next((p["q"] for p in ps if p["q"]), "?")
        if flt and flt not in q:
            continue
        replies = [p for p in ps if p["qr"] == 1]
        nfrag = max((p["frag"][1] for p in replies if p["frag"]), default=0)
        proto = "TCP" if any(p["proto"] == "TCP" for p in ps) else "UDP"
        ms = (max(p["t"] for p in ps) - min(p["t"] for p in ps)) * 1000
        nbytes = sum(p["len"] for p in ps)
        notes = []
        if any(p["opcode"] == 7 for p in ps):
            notes.append("RAW")
        if any(p.get("tc") == 1 for p in replies):
            notes.append("TC")
        if any(p["q"] and p["q"].startswith("?") for p in ps):
            notes.append("QBF")
        tot["tx"] += 1
        tot["dgrams"] += len(ps)
        tot["bytes"] += nbytes
        if nfrag > 1:
            tot["frag_tx"] += 1
        if proto == "TCP":
            tot["tcp_tx"] += 1
        if nfrag > 1 or proto == "TCP" or len(ps) > 2:
            print(f"{q[:40]:40} {proto:5} {len(ps):6} {nbytes:7} {nfrag:5} {ms:7.1f}  {' '.join(notes)}")
    print()
    print(f"transactions: {tot['tx']}  fragmented: {tot['frag_tx']}  over TCP: {tot['tcp_tx']}  "
          f"datagrams: {tot['dgrams']}  bytes: {tot['bytes']}")


if __name__ == "__main__":
    main()
