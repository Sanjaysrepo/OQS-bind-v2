"""Check 1-RTT behaviour in a capture (pcapdump.py output or .pcap).

For every fragmented transaction towards the authoritative server,
checks whether all fragment requests were sent *before* the first
fragment reply arrived (speculative / 1-RTT), only some of them (the
estimate was too low or requests left late; the rest followed the
first reply) or none of them (2-RTT).  Only traffic with the authoritative server is
counted - the resolver's and dig's direct queries; the dig <-> resolver
loopback hop is skipped.

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
    # per transaction: capture positions of fragment requests and replies
    # (capture order, not timestamps: those have 0.1 ms resolution)
    tx = defaultdict(lambda: {"req": [], "reply": [], "frag": False})
    cur = None
    pos = 0
    for line in load(sys.argv[1]):
        m = HDR.match(line)
        if m:
            pos += 1
            cur = {"pos": pos, "loop": "127.0.0.1" in (m[3], m[5])}
            continue
        if cur is None or cur["loop"]:
            continue
        m = IDL.match(line)
        if m:
            t = tx[m[1]]
            if int(m[2]) == 0 and int(m[3]) == 7:
                t["req"].append(cur["pos"])
            elif int(m[2]) == 1:
                t["reply"].append(cur["pos"])
                cur["id"] = m[1]
            continue
        if OPT.search(line) and "id" in cur:
            tx[cur["id"]]["frag"] = True

    one_rtt = topped_up = two_rtt = 0
    for txid, t in tx.items():
        if not t["req"] or not t["frag"]:
            continue
        first_reply = min(t["reply"])
        if max(t["req"]) < first_reply:
            # every request left with the query: one round trip
            one_rtt += 1
        elif min(t["req"]) < first_reply:
            # some requests left with the query, the rest only after the
            # first reply (estimate too low, or requests sent late)
            topped_up += 1
        else:
            two_rtt += 1
    total = one_rtt + topped_up + two_rtt
    print(f"fragmented transactions with requests: {total}, "
          f"1-RTT (all requests sent with the query): {one_rtt}, "
          f"more than 1 RTT: {topped_up + two_rtt} "
          f"({topped_up} with only part of the requests sent with the query, "
          f"{two_rtt} with none)")
    sys.exit(0 if one_rtt > 0 else 1)


if __name__ == "__main__":
    main()
