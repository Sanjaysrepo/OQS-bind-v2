
# Changes
OQS-Bind is currently lacking hybrid signatures, such as p256_falcon512.
Hybrid signatures are supported by oqs-provider https://github.com/open-quantum-safe/oqs-provider.
PQC algorithms might still be vulnerable because of their infancy.
Bringing hybrid signatures to bind9 allows us transition safely to quantum-safe algorithms by combining traditional signature schemes with post-quantum signature schemes.

This version of OQS-bind adds two things:
1. Support for hybrid signature schemes
2. Support for UDP fragmentation

# OQS-Bind
[![CodeQL](https://github.com/Martyrshot/OQS-bind/actions/workflows/codeql.yml/badge.svg)](https://github.com/Martyrshot/OQS-bind/actions/workflows/codeql.yml)

OQS-Bind is a forked version of ISC's [Bind9](https://gitlab.isc.org/isc-projects/bind9) DNS software
which enables PQC DNS. The original Bind9 README can be found [here](ORIGINAL_README.md). This fork
take advantage of [Open Quantum Safe](https://github.com/open-quantum-safe)'s
[liboqs](https://github.com/open-quantum-safe/liboqs) and [oqs-provider](https://github.com/open-quantum-safe/oqs-provider).
**NOTE:** OpenSSL 3.2 is **REQUIRED** to build and use OQS-Bind.

This project is not officially affiliated with Open Quantum Safe.

## Algorithms
Currently only DNSSEC is supported and tested with a small number of algorithms,
but DoT and DoH inprinciple should work. I plan on eventually enabling more DNSSEC PQC algorithms in the
future and automating enabling and disabling them, but for now this must be done by hand. The algorithms
we support in DNSSEC are as follows:

### DNSSEC Algorithms
For an overview of all algorithms supported by oqs-provider, click [here](https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md).

|            Algorithm         | DNSSEC Algorithm ID | Hybrid | Implemented |
| ---------------------------- | ------------------- | ------ | ----------- |
| falconpadded512              |         17          | No     | Yes         |
| p256_falconpadded512         |         18          | Yes    | Yes         |
| rsa3072_falconpadded512      |         19          | Yes    | Yes         |
| falconpadded1024             |         20          | No     | Yes         |
| p521_falconpadded1024        |         21          | Yes    | Yes         |
| mldsa44                      |         22          | No     | Yes         |
| p256_mldsa44                 |         23          | Yes    | Yes         |
| rsa3072_mldsa44              |         24          | Yes    | Yes         |
| slhdsasha2128s               |         25          | No     | Yes         |
| p256_slhdsasha2128s          |         26          | Yes    | Yes         |
| rsa3072_slhdsasha2128s       |         27          | Yes    | Yes         |
| mayo1                        |         28          | No     | Yes         |
| p256_mayo1                   |         29          | Yes    | Yes         |
| snova2454                    |         30          | No     | Yes         |
| p256_snova2454               |         31          | Yes    | Yes         |

We opted to start the algorithm IDs at 17 because of the discussion seen
[here](https://mailarchive.ietf.org/arch/msg/dnsop/2xKvE-g1WU5VozEDN7-h2e5y-MQ/).

### DoT/DoH Algorithms
These have not been tested, but in principle all algorithms supported by
[oqs-proivder](https://github.com/open-quantum-safe/oqs-provider) should work.

## Building

In order to build OQS-Bind, some version of OpenSSL 3.2 must be installed. At the time
of writing Beta1 just was released, so it is recommended to not use OpenSSL 3.2 as your
primary system-wide instalation of OpenSSL. Instead, installed OpenSSL 3.2 in a special
location. You can then specify the location of OpenSSL 3.2 using the `--with-openssl=<OPENSSL3.2DIR>`.
Then simply follow the regular Bind9 build instructions found [here](https://github.com/Martyrshot/OQS-bind/blob/main/doc/arm/build.inc.rst).

## UDP fragmentation

PQC signatures and keys make DNSSEC replies far larger than the 1232-byte
UDP limit, so a stock resolver would fall back to TCP for almost every
signed answer.  OQS-Bind can instead split a reply into several UDP
datagrams that the resolver requests and reassembles itself.  Enable it
in `named.conf` on **both** the authoritative server and the resolver:

```
options {
	udp-fragmentation RAW;   // or QBF
};
```

| Mode | How it works | Limits |
| ---- | ------------ | ------ |
| `QBF` | Every fragment is a normal DNS message; only DNSKEY/RRSIG RDATA is split proportionally across fragments. Fragments carry TC=1 and EDNS option 22; the resolver asks for more with `?N?qname` queries. | Only DNSKEY/RRSIG are split; depends on RR order; TC is ambiguous. |
| `RAW` | The complete rendered reply is cut into byte slices. Each fragment is a tiny envelope (RCODE 12, the question, EDNS option 22 `<frag:6><total:6><flags:4>`) followed by a raw slice. The resolver asks for fragment *n* with an OPCODE 7 query carrying option 22 and concatenates the slices, which reproduces the original datagram byte for byte. | 63 fragments (~75 KB); requires EDNS on the client. |

RAW works for any record type and size (SPHINCS+ signatures, Falcon-1024
keys, hybrid keys) and needs no changes to the resource records.  In RAW
mode the resolver also runs in **1-RTT mode**: alongside a query that may
get a fragmented answer (EDNS with DO set) it sends speculative fragment
requests - as many as the last fragmented reply of that server needed
(per-server history, default and cap 4) - so the complete answer arrives
in a single round trip.  A server that does not fragment, or an answer
that needs no fragmentation, answers them with OPCODE 7 error echoes
that the resolver ignores; an answer with more fragments than estimated
has the remainder requested when fragment 0 arrives (two-step).  A
resolver that does not understand RAW sees RCODE 12 and treats the reply
as an error rather than caching an empty answer; clients without EDNS get
the usual truncated (TC) reply and retry over TCP.  The full wire format
is documented in [lib/dns/include/dns/raw.h](lib/dns/include/dns/raw.h);
the fragment cache is in `lib/dns/fcache.c`, the server hook in
`ns_client_send()` (`lib/ns/client.c`) and the resolver hook in
`udp_recv()` (`lib/dns/dispatch.c`).  `dig` understands RAW fragments as
well, so `dig @auth zone DNSKEY +dnssec` shows the reassembled answer.

### Testing

Unit tests (`tests/dns`): `raw_test`, `qbf_test`, `fcache_test` and
`udp_fragmentation_test` fragment and reassemble real PQC responses from
`tests/dns/testdata/message`.

End-to-end (`e2e/`): a Docker Compose test bed with an authoritative
server for `.`, `test.` and `example.test.` signed with a PQC algorithm
of your choice and a validating resolver, both running with
`udp-fragmentation`.  `run_tests.sh` queries through the resolver and
straight at the authoritative server, compares UDP with TCP answers,
captures a pcap and prints a PASS/FAIL table:

```
docker build -f Dockerfile.deps -t oqs-bind-deps .   # once
e2e/run_tests.sh P256_FALCON512 RAW
e2e/run_tests.sh SLHDSASHA2128S RAW
e2e/run_tests.sh P256_FALCON512 QBF
```

Results land in `e2e/results/<MODE>_<ALG>/` and captures in
`e2e/captures/`; `e2e/tools/pcapdump.py` decodes the captures (including
EDNS option 22) without Wireshark and `e2e/tools/pcapstats.py` summarises
them per transaction.  [e2e/RESULTS.md](e2e/RESULTS.md) has the results
of all scenarios and a comparison of RAW with the reference QBF capture.

# 2.0 release features
- ~~Fully implement and test RAW~~
- ~~Use `rcodes` and `flags` to indicate fragments~~ (RAW: RCODE 12, OPCODE 7)
- Remove DNSKEY/RRSIG header duplicates (QBF)
- ~~Improve render function and don't attach buffer to object~~ (RAW renders once into its own buffer)
- ~~Add more unit tests~~
- Improve performance