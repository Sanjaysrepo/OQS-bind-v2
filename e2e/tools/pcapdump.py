"""Decode a pcap of DNS traffic without Wireshark/tshark.

Prints one block per packet: timestamp, addresses, DNS header (id, flags,
opcode, rcode, section counts), the question, a summary of each resource
record and the full EDNS OPT including option 22 (UDP fragmentation:
fragment number / total / flags).  Understands Ethernet, Linux cooked v1/v2
and raw-IP captures, UDP and TCP (length-prefixed) payloads.

Usage: pcapdump.py <file.pcap>
"""
import struct, sys

TYPES = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",16:"TXT",28:"AAAA",33:"SRV",41:"OPT",43:"DS",46:"RRSIG",47:"NSEC",48:"DNSKEY",50:"NSEC3",51:"NSEC3PARAM",255:"ANY"}

def rdname(buf, off, depth=0):
    labels = []
    jumped = False
    end = None
    while True:
        if off >= len(buf):
            return "<trunc>", off
        l = buf[off]
        if l == 0:
            off += 1
            break
        if (l & 0xC0) == 0xC0:
            ptr = struct.unpack("!H", buf[off:off+2])[0] & 0x3FFF
            if end is None: end = off + 2
            if depth > 20: return "<loop>", end
            name, _ = rdname(buf, ptr, depth+1)
            labels.append(name)
            off = end
            jumped = True
            break
        off += 1
        labels.append(buf[off:off+l].decode("latin1"))
        off += l
    if jumped:
        return ".".join(labels), off
    return (".".join(labels) or ".") , (end if end else off)

def parse_dns(buf):
    if len(buf) < 12:
        return {"err": "short"}
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    out = {"id": ident, "qr": flags>>15, "opcode": (flags>>11)&0xF, "aa": (flags>>10)&1, "tc": (flags>>9)&1,
           "rd": (flags>>8)&1, "ra": (flags>>7)&1, "ad": (flags>>5)&1, "cd": (flags>>4)&1, "rcode": flags&0xF,
           "qd": qd, "an": an, "ns": ns, "ar": ar, "len": len(buf), "q": [], "rrs": [], "opt": None}
    off = 12
    try:
        for _ in range(qd):
            n, off = rdname(buf, off)
            t, c = struct.unpack("!HH", buf[off:off+4]); off += 4
            out["q"].append((n, TYPES.get(t, t), c))
        for sec, cnt in (("AN", an), ("NS", ns), ("AR", ar)):
            for _ in range(cnt):
                n, off = rdname(buf, off)
                t, c, ttl, rdl = struct.unpack("!HHIH", buf[off:off+10]); off += 10
                rd = buf[off:off+rdl]
                if t == 41:
                    ext_rcode = ttl >> 24; ver = (ttl >> 16) & 0xFF; eflags = ttl & 0xFFFF
                    opts = []
                    o = 0
                    while o + 4 <= len(rd):
                        code, ln = struct.unpack("!HH", rd[o:o+4]); o += 4
                        val = rd[o:o+ln]; o += ln
                        d = {"code": code, "len": ln, "hex": val.hex()}
                        if code == 22 and ln == 2:
                            v = struct.unpack("!H", val)[0]
                            d["frag_nr"] = (v >> 10) & 0x3F; d["nr_frags"] = (v >> 4) & 0x3F; d["flags"] = v & 0xF
                        opts.append(d)
                    out["opt"] = {"udpsize": c, "ext_rcode": ext_rcode, "ver": ver, "DO": eflags>>15, "opts": opts, "rdlen": rdl, "trunc_rd": len(rd) < rdl}
                else:
                    extra = ""
                    if t == 48 and len(rd) >= 4:
                        extra = f" flags={struct.unpack('!H', rd[:2])[0]} alg={rd[3]}"
                    elif t == 46 and len(rd) >= 18:
                        extra = f" covers={TYPES.get(struct.unpack('!H', rd[:2])[0])} alg={rd[2]}"
                    out["rrs"].append((sec, n, TYPES.get(t, t), rdl, len(rd), extra))
                off += rdl
    except Exception as e:
        out["parse_err"] = repr(e)
    out["consumed"] = off
    return out

def main(path):
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xa1b2c3d4: endian = "<"; nano = False
    elif magic == 0xd4c3b2a1: endian = ">"; nano = False
    elif magic == 0xa1b23c4d: endian = "<"; nano = True
    elif magic == 0x4d3cb2a1: endian = ">"; nano = True
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        print("pcapng not supported by this script"); return
    else:
        print("unknown magic", hex(magic)); return
    linktype = struct.unpack(endian+"I", data[20:24])[0]
    print("linktype", linktype)
    off = 24; n = 0; t0 = None
    while off + 16 <= len(data):
        ts_s, ts_u, incl, orig = struct.unpack(endian+"IIII", data[off:off+16]); off += 16
        pkt = data[off:off+incl]; off += incl; n += 1
        ts = ts_s + ts_u/(1e9 if nano else 1e6)
        if t0 is None: t0 = ts
        if linktype == 1:
            eth = struct.unpack("!H", pkt[12:14])[0]; l3 = pkt[14:]
        elif linktype == 113:
            eth = struct.unpack("!H", pkt[14:16])[0]; l3 = pkt[16:]
        elif linktype == 101:
            eth = 0x0800; l3 = pkt
        elif linktype == 0:
            eth = 0x0800 if pkt[0]==2 else 0x86dd; l3 = pkt[4:]
        elif linktype == 276:  # LINUX_SLL2
            eth = struct.unpack("!H", pkt[0:2])[0]; l3 = pkt[20:]
        else:
            print(n, "unhandled linktype"); continue
        if eth == 0x0800:
            ihl = (l3[0] & 0xF) * 4; proto = l3[9]; tot = struct.unpack("!H", l3[2:4])[0]
            ipid = struct.unpack("!H", l3[4:6])[0]; fragf = struct.unpack("!H", l3[6:8])[0]
            src = ".".join(map(str, l3[12:16])); dst = ".".join(map(str, l3[16:20])); l4 = l3[ihl:]
            ipinfo = f"ipid={ipid} MF={(fragf>>13)&1} off={fragf&0x1FFF}"
        elif eth == 0x86dd:
            proto = l3[6]; src = l3[8:24].hex(); dst = l3[24:40].hex(); l4 = l3[40:]; ipinfo = ""
        else:
            print(f"#{n} non-IP ethertype {hex(eth)}"); continue
        if proto == 17:
            sp, dp, ul, _ = struct.unpack("!HHHH", l4[:8]); payload = l4[8:]
            proto_s = "UDP"
        elif proto == 6:
            sp, dp = struct.unpack("!HH", l4[:4]); doff = (l4[12] >> 4) * 4; payload = l4[doff:]; proto_s = "TCP"
            if len(payload) >= 2:
                payload = payload[2:]  # strip 2-byte length prefix (best-effort)
            else:
                print(f"#{n} t=+{ts-t0:.4f}s TCP {src}:{sp} -> {dst}:{dp} (no payload, len={len(l4)-doff})"); continue
        else:
            print(f"#{n} proto {proto}"); continue
        d = parse_dns(payload)
        print(f"\n#{n} t=+{ts-t0:.4f}s {proto_s} {src}:{sp} -> {dst}:{dp} udp/tcp payload={len(payload)}B {ipinfo}")
        if "err" in d:
            print("   ", d); continue
        print(f"    id=0x{d['id']:04x} qr={d['qr']} opcode={d['opcode']} aa={d['aa']} tc={d['tc']} rd={d['rd']} ra={d['ra']} ad={d['ad']} rcode={d['rcode']} counts qd/an/ns/ar={d['qd']}/{d['an']}/{d['ns']}/{d['ar']}")
        for q in d["q"]:
            print(f"    Q: {q}")
        for r in d["rrs"]:
            print(f"    {r[0]}: {r[1]} {r[2]} rdlen={r[3]} have={r[4]}{r[5]}")
        if d["opt"]:
            print(f"    OPT: {d['opt']}")
        if "parse_err" in d:
            print("    parse_err:", d["parse_err"], "consumed", d["consumed"])
    print("\nTotal packets:", n)

main(sys.argv[1])
