# RAW UDP fragmentation — test results

Environment: Docker (Debian trixie, OpenSSL 3.5.7, liboqs + oqs-provider
from `main` on 2026-08-28), OQS-bind built from this repository, two
containers on a private network: an authoritative server for `.`, `test.`
and `example.test.` (zones signed at start-up) and a validating resolver
with the root KSK as trust anchor.  `edns-udp-size`/`max-udp-size` 1232 on
both.  Produced by `e2e/run_tests.sh <ALG> <MODE>`; raw outputs are in
`e2e/results/<MODE>_<ALG>/` and captures in `e2e/captures/`.

## 1. Unit tests (`tests/dns`)

| suite | tests | result |
| ----- | ----- | ------ |
| `raw_test` | fragment + reassemble five real PQC responses (Falcon-512, P256+Falcon-512, Dilithium; 3–7 fragments), envelope parser edge cases | 2/2 pass |
| `udp_fragmentation_test` | option 22 encode/decode, OPT manipulation, QBF `?N?` and RAW OPCODE 7 request builders | 6/6 pass |
| `qbf_test` | QBF fragment + reassemble (regression) | 1/1 pass |
| `fcache_test` | cache add/remove/expiry with timers | 7/7 pass |

Reassembled output is compared byte for byte with the original datagram.

## 2. End-to-end: RAW, P256_FALCON512 (hybrid, alg 18)

| check | result | detail |
| ----- | ------ | ------ |
| resolver: `test.example.test A` | PASS | NOERROR, flags `qr rd ra ad` |
| resolver: answer DNSSEC-validated (`ad`) | PASS | |
| resolver: `. DNSKEY` | PASS | NOERROR, 3562 B |
| resolver: `test DNSKEY` | PASS | NOERROR, 3577 B |
| resolver: `example.test DNSKEY` | PASS | NOERROR, 3604 B |
| resolver: `test0..test9.example.test A` in a row | PASS | 10/10 |
| dig@auth: `example.test DNSKEY` UDP vs TCP | PASS | both NOERROR, 3604 B, no TC |
| dig@auth: `test.example.test A` UDP vs TCP | PASS | 2478 B both |
| dig@auth: client without EDNS gets TC fallback | PASS | (after fixing the test: `+dnssec` re-enabled EDNS) |
| capture: RAW fragments and OPCODE 7 requests seen | PASS | 109 fragment datagrams, 44 requests, 0 TC, TCP only for the explicit `+tcp` controls |

The resolver's own answers to `dig` (3.5 KB DNSKEY sets) are fragmented
again on the resolver→dig hop and reassembled by dig's RAW client.

## 3. Capture comparison: RAW vs the reference QBF capture

`e2e/tools/pcapstats.py` groups datagrams per transaction.  Left: this
implementation (`captures/RAW_P256_FALCON512.pcap`); right: the reference
`QBF_P256_FALCON512_1.pcap` supplied with the project (same algorithm,
equivalent zone layout `. → local → example.local`).

| transaction | RAW datagrams | RAW bytes | QBF datagrams | QBF bytes |
| ----------- | ------------: | --------: | ------------: | --------: |
| signed `A` answer (2 RRSIGs + glue) | 6 (3 fragments) | 2812 | 6 (3 fragments) | 3003–3010 |
| `example.*` DNSKEY (2 keys + 2 RRSIGs) | 8 (4 fragments) | 3986 | 8 (4 fragments) | 4287 |
| `.` DNSKEY | 6 (3 fragments) | 3772 | 8 (4 fragments) | 4051 |
| `ns1.* AAAA` (NODATA, 2 RRSIGs) | 4 (2 fragments) | 1899–1955 | 4 (2 fragments) | 1878–1954 |
| replies flagged TC | 0 | | all fragments | |
| TCP fallbacks | 0 | | 0 | |

Observations:

* Fragment counts are identical or lower.  RAW's per-fragment overhead is
  a fixed 34-byte envelope (header 12 + question + 17-byte OPT); QBF
  repeats the owner names, the DNSKEY/RRSIG RDATA headers and the OPT in
  every fragment and its `?N?qname` requests are longer, which costs
  6–7 % more bytes for the same data.
* RAW reassembly is a byte concatenation; the reassembled datagram is the
  original rendering, so cookies, TSIG and any RR type survive.  QBF can
  only split DNSKEY and RRSIG RDATA and relies on RR order.
* RAW fragments carry RCODE 12 instead of TC, so a resolver without RAW
  support treats them as an error and moves on, rather than mistaking a
  fragment for a truncated reply or an empty answer.
* Latencies in the reference capture (5–130 ms) are dominated by its
  network; in the local test bed a complete 3-fragment exchange takes
  0.4–0.7 ms.  The extra cost of fragmentation is one round trip: the
  resolver fires all remaining requests as soon as fragment 0 arrives.

## 4. All scenarios (final code, `run_tests.sh <ALG> <MODE>`)

| scenario | checks | resolver DNSKEY reply sizes | largest exchange | capture totals |
| -------- | ------ | --------------------------- | ---------------- | -------------- |
| RAW, P256_FALCON512 (hybrid, **1-RTT**) | 12/12 pass | 3562 / 3580 / 3603 B | 4 fragments (`example.test DNSKEY`) | 15 of 17 fragmented tx complete in a single round trip (speculative requests); 0 TCP |
| RAW resolver against a server **without** fragmentation (interop) | 10/10 pass | 3560 / 3580 / 3604 B | — | speculative requests answered NOTIMP and ignored; resolution falls back to TC/TCP as stock BIND |
| RAW, SLHDSASHA2128S (SPHINCS+, 7.8 KB signatures) | 11/11 pass | 15922 / 15941 / 15965 B | **21 fragments** (24 KB signed `A` answer: A + 3 RRSIGs + glue), 14 for a DNSKEY set | 41 tx, 34 fragmented, 612 KB; TCP only for the explicit `+tcp` controls |
| RAW, FALCON1024 (single DNSKEY 1793 B > one fragment) | 10/10 pass | 6292 / 6311 / 6335 B | 6 fragments (DNSKEY sets) | 38 tx, 34 fragmented |
| QBF, P256_FALCON512 (existing scheme, regression) | 10/10 pass | 3560 / 3577 / 3603 B | 4 fragments | resolver↔auth entirely over UDP; TCP only for dig's own hops (dig speaks RAW, not QBF) and the deliberate `+tcp` controls |
| none, P256_FALCON512 (baseline) | 9/9 pass | 3560 / 3578 / 3603 B | — | 57 tx, 0 fragmented, **22 over TCP** (every large reply truncated and retried) |

Notes:

* SPHINCS+ is the case RAW was built for: a single RRSIG (7856 B) is
  larger than six fragments, so per-RR splitting (QBF) cannot work; RAW
  slices straight through it and the reply validates (`ad`).
* Falcon-1024 exercises an RR (1793 B DNSKEY) larger than one fragment.
* QBF and DNS cookies: QBF's reassembled replies do not carry a valid
  server COOKIE (RFC 7873), so a cookie-aware resolver re-fetches every
  such answer over TCP as anti-spoofing.  The reference QBF capture
  contains no COOKIE options at all, i.e. the original test bed ran with
  cookies disabled; the QBF test bed now does the same (`send-cookie
  no;`), after which the resolver↔auth traffic is entirely UDP, matching
  the reference.  RAW needs no such exception: its reassembly reproduces
  the original datagram byte for byte, cookie included, so it passes the
  cookie check and never falls back to TCP even with cookies enabled.
  (`dig` has no QBF client — it only speaks RAW — so `dig` pointed
  straight at a QBF server still retries over TCP; that is inherent to
  QBF and unchanged from the original implementation.)
* Without EDNS there is no DO bit, so the answer either fits (SPHINCS+
  public keys are 32 B) or is truncated; both are accepted by the check.
* The "no assertion failures" check found a real bug: the fragment cache
  was destroyed from the per-dispatch destructor on a worker thread,
  which crashed the resolver as soon as it used TCP in QBF mode.  Both
  caches are now torn down from `shutdown_server()` on the main loop.

### 1-RTT mode

In RAW mode the resolver sends speculative OPCODE 7 fragment requests
together with the query (as many as the per-server fragment history
suggests, default and cap 4), so a fragmented answer completes in a
single round trip instead of two:

```
t=+0.0 ms  resolver -> auth   QUERY
t=+0.1 ms  resolver -> auth   FRAG REQUEST 1/3   (speculative)
t=+0.1 ms  resolver -> auth   FRAG REQUEST 2/3   (speculative)
t=+0.2 ms  auth -> resolver   FRAG REPLY   0/3
t=+0.4 ms  auth -> resolver   FRAG REPLY   1/3
t=+0.4 ms  auth -> resolver   FRAG REPLY   2/3
```

Safety properties: requests are only prefetched for queries with EDNS
and the DO bit (unsigned answers never fragment); the burst is capped at
4; a wrong estimate degrades to the two-step flow (remainder requested
when fragment 0 arrives) or to ignored OPCODE 7 error echoes; and
against a server without fragmentation support resolution proceeds
exactly as stock BIND (verified by the interop scenario above).

## 5. Performance notes

* Server: one extra full render of the reply into a 64 KB scratch buffer
  when the reply might be large; the normal render is skipped when it is
  fragmented.  QBF rendered every fragment twice.
* Per fragment: one small envelope render (question + OPT) and a memcpy.
* Resolver: fragments are cached as raw datagrams; reassembly is a single
  allocation and N memcpys, no message parsing until the resolver parses
  the reassembled reply as usual.
* Cache entries: server side 30 s, resolver side 10 s, swept by a ticker;
  the cache is protected by a mutex (it is shared by all worker threads).
