"""Check 1-RTT behaviour in a capture (pcapdump.py output or .pcap).

For every fragmented transaction towards the authoritative server,
checks whether the fragment requests were sent *before* the first
fragment reply arrived (speculative / 1-RTT) or only afterwards (2-RTT).

Usage: check1rtt.py <pcapdump-output.txt | file.pcap>
Exit code 0 when at least one 1-RTT transaction is present.
"""
import os
import re
import subprocess
import sys
from collections import defaultdict

HDR = re.compile(r"^#\d+ t=\+([\d.]+)s (UDP|TCP) ([\d.]+):(\d+) -> ([\d.]+):(\d+)")
IDL = re.compile(r"^\s+id=0x([0-9a-f]+) qr=(\d) opcode=(\d+)")
OPT = re.compile(r"'frag_nr': (\d+), 'nr_frags': (\d+)")


def load(path):
    if path.endswith(".pcap"):
        here = os.path.dirname(os.path.abspath(__file__))
        return subprocess.run(
            [sys.executable, os.path.join(here, "pcapdump.py"), path],
            capture_output=True, text=True).stdout.splitlines()
    return open(path, encoding="utf-8", errors="replace").read().splitlines()


def main():
    tx = defaultdict(lambda: {"req": [], "frag_reply": []})
    cur = None
    for line in load(sys.argv[1]):
        m = HDR.match(line)
        if m:
            cur = {"t": float(m[1]), "loop": "127.0.0.1" in (m[3], m[5])}
            continue
        if cur is None:
            continue
        m = IDL.match(line)
        if m and not cur["loop"]:
            cur.update(id=m[1], qr=int(m[2]), op=int(m[3]))
            continue
        m = OPT.search(line)
        if m and cur and "id" in cur and not cur["loop"]:
            t = tx[cur["id"]]
            if cur["qr"] == 0 and cur["op"] == 7:
                t["req"].append(cur["t"])
            elif cur["qr"] == 1:
                t["frag_reply"].append(cur["t"])

    one_rtt = two_rtt = 0
    for txid, t in tx.items():
        if not t["req"] or not t["frag_reply"]:
            continue
        # speculative: the first fragment request left before any
        # fragment reply had arrived
        if min(t["req"]) <= min(t["frag_reply"]):
            one_rtt += 1
        else:
            two_rtt += 1
    print(f"fragmented transactions with requests: {one_rtt + two_rtt}, "
          f"1-RTT (speculative requests): {one_rtt}, 2-RTT: {two_rtt}")
    sys.exit(0 if one_rtt > 0 else 1)


if __name__ == "__main__":
    main()
