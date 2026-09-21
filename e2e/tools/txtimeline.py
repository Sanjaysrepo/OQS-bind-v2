"""Print the packet timeline of fragmented DNS transactions in a capture.

For each fragmented transaction shows every datagram with a relative
timestamp, source/destination (with ports) and its role (query, fragment
request n/N, fragment reply n/N).  Makes two properties easy to see:

  * every query transaction uses its own client port, and the fragment
    requests reuse that port (so the replies reach the right socket);
  * all remaining fragments are requested in one burst right after
    fragment 0 arrives, i.e. the whole exchange costs one extra RTT.

Usage: txtimeline.py <pcapdump-output.txt | file.pcap> [max_transactions]
"""
import os
import re
import subprocess
import sys
from collections import defaultdict

HDR = re.compile(r"^#(\d+) t=\+([\d.]+)s (UDP|TCP) ([\d.]+):(\d+) -> ([\d.]+):(\d+)")
IDL = re.compile(r"^\s+id=0x([0-9a-f]+) qr=(\d) opcode=(\d+)")
OPT = re.compile(r"'frag_nr': (\d+), 'nr_frags': (\d+)")
QL = re.compile(r"^\s+Q: \('([^']*)'")


def load(path):
    if path.endswith(".pcap"):
        here = os.path.dirname(os.path.abspath(__file__))
        text = subprocess.run(
            [sys.executable, os.path.join(here, "pcapdump.py"), path],
            capture_output=True, text=True).stdout
    else:
        text = open(path, encoding="utf-8", errors="replace").read()
    pkts = []
    cur = None
    for line in text.splitlines():
        m = HDR.match(line)
        if m:
            cur = {"t": float(m[2]), "src": f"{m[4]}:{m[5]}",
                   "dst": f"{m[6]}:{m[7]}"}
            pkts.append(cur)
            continue
        if cur is None:
            continue
        m = IDL.match(line)
        if m:
            cur.update(id=m[1], qr=int(m[2]), op=int(m[3]))
        m = QL.match(line)
        if m and "q" not in cur:
            cur["q"] = m[1]
        m = OPT.search(line)
        if m:
            cur["frag"] = (int(m[1]), int(m[2]))
    return pkts


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    tx = defaultdict(list)
    for p in load(sys.argv[1]):
        if "id" in p:
            tx[p["id"]].append(p)

    shown = 0
    for txid, ps in sorted(tx.items(), key=lambda kv: kv[1][0]["t"]):
        if not any(p.get("frag") for p in ps) or len(ps) < 6:
            continue
        print(f"--- transaction id=0x{txid}  query: {ps[0].get('q', '?')} ---")
        t0 = ps[0]["t"]
        for p in ps:
            if p["qr"] == 0 and p["op"] == 0 and not p.get("frag"):
                kind = "QUERY"
            elif p["qr"] == 0:
                kind = "FRAG REQUEST %d/%d" % p.get("frag", (0, 0))
            elif p.get("frag"):
                kind = "FRAG REPLY   %d/%d" % p["frag"]
            else:
                kind = "REPLY"
            print(f"  t=+{(p['t'] - t0) * 1000:6.2f} ms  "
                  f"{p['src']:>22} -> {p['dst']:<20} {kind}")
        print()
        shown += 1
        if shown >= limit:
            break


if __name__ == "__main__":
    main()
