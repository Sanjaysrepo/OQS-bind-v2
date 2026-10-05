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
| `raw_test` | fragment + reassemble five real PQC responses (Falcon-512, P256+Falcon-512, Dilithium; 3–7 fragments), envelope parser edge cases, 1-RTT candidate check, request builder (byte-identical to the renderer), lost-request detection | 4/4 pass |
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
| signed `A` answer (2 RRSIGs + glue) | 8 (3 fragments) | 2870–2896 | 6 (3 fragments) | 3003–3010 |
| `example.*` DNSKEY (2 keys + 2 RRSIGs) | 8 (4 fragments) | 3986–4002 | 8 (4 fragments) | 4287 |
| `.` DNSKEY | 8 (3 fragments) | 3829 | 8 (4 fragments) | 4051 |
| `ns1.* AAAA` (NODATA, 2 RRSIGs) | 8 (2 fragments) | 2103 | 4 (2 fragments) | 1878–1954 |
| replies flagged TC | 0 | | all fragments | |
| TCP fallbacks | 0 | | 0 | |

RAW datagram counts include the 1-RTT speculative requests (3 with the
default estimate of 4) and, when the answer has fewer than 4 fragments,
their echoes.

Observations:

* Fragment counts are identical or lower.  RAW's per-fragment overhead is
  a fixed 34-byte envelope (header 12 + question + 17-byte OPT); QBF
  repeats the owner names, the DNSKEY/RRSIG RDATA headers and the OPT in
  every fragment and its `?N?qname` requests are longer.  For answers of
  3–4 fragments RAW therefore uses 4–7 % fewer bytes than QBF even with
  the 1-RTT requests included.
* The price of 1-RTT mode: answers with fewer fragments than estimated
  (2-fragment answers, and signed answers that are not fragmented at
  all) carry up to 3 unneeded requests and 3 echoes, about 170-230 bytes and
  6 small datagrams per exchange - so the 2-fragment `AAAA` above costs
  slightly more than QBF.  In exchange, a fragmented answer whose size
  is estimated right costs no extra round trip.
* RAW reassembly is a byte concatenation; the reassembled datagram is the
  original rendering, so cookies, TSIG and any RR type survive.  QBF can
  only split DNSKEY and RRSIG RDATA and relies on RR order.
* RAW fragments carry RCODE 12 instead of TC, so a resolver without RAW
  support treats them as an error and moves on, rather than mistaking a
  fragment for a truncated reply or an empty answer.
* Latencies in the reference capture (5–130 ms) are dominated by its
  network; in the local test bed a complete 3-fragment exchange takes
  0.2–0.3 ms with 1-RTT mode (0.3–1.0 ms without).  A local round trip
  is only ~0.1 ms, so these figures understate the benefit: on a real
  network 1-RTT mode saves one full round trip per fragmented answer.

## 4. All scenarios (final code, `run_tests.sh <ALG> <MODE>`)

| scenario | checks | resolver DNSKEY reply sizes | largest exchange | capture totals |
| -------- | ------ | --------------------------- | ---------------- | -------------- |
| RAW, P256_FALCON512 (hybrid, **1-RTT**) | 12/12 pass | 3562 / 3577 / 3604 B | 4 fragments (`example.test DNSKEY`) | **17 of 17** fragmented exchanges with the authoritative server complete in a single round trip; 0 TCP |
| RAW resolver against a server **without** fragmentation (interop) | 10/10 pass | 3560 / 3578 / 3603 B | — | speculative requests answered NOTIMP and ignored; resolution falls back to TC/TCP as stock BIND |
| RAW, SLHDSASHA2128S (SPHINCS+, 7.8 KB signatures) | 12/12 pass | 15922 / 15941 / 15965 B | **21 fragments** (24 KB signed `A` answer: A + 3 RRSIGs + glue), 14 for a DNSKEY set | 1-RTT: 16 of 20 exchanges with the authoritative server in one round trip (the other 4: dig's two direct queries - dig keeps no history and starts at 4 - the resolver's first `A` query, and an `A` answer larger than the previous one); TCP only for the explicit `+tcp` controls |
| RAW, FALCON1024 (single DNSKEY 1793 B > one fragment) | 12/12 pass | 6292 / 6311 / 6335 B | 6 fragments (DNSKEY sets) | 1-RTT: 19 of 20 exchanges with the authoritative server in one round trip |
| QBF, P256_FALCON512 (existing scheme, regression) | 10/10 pass | 3561 / 3579 / 3603 B | 4 fragments | resolver↔auth entirely over UDP; TCP only for dig's own hops (dig speaks RAW, not QBF) and the deliberate `+tcp` controls |
| none, P256_FALCON512 (baseline) | 10/10 pass | 3558 / 3579 / 3603 B | — | 57 tx, 0 fragmented, **22 over TCP** (every large reply truncated and retried) |

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
* DNSKEY reply sizes vary by a few bytes between runs: the zones are
  signed afresh at every start and ECDSA / Falcon signatures vary in
  length.
* The OPCODE 7 requests in the QBF and baseline captures are `dig`'s
  speculative 1-RTT requests on the dig -> resolver hop; a resolver not
  in RAW mode answers them NOTIMP and `dig` ignores the echoes.
* Without EDNS there is no DO bit, so the answer either fits (SPHINCS+
  public keys are 32 B) or is truncated; both are accepted by the check.
* The "no assertion failures" check found a real bug: the fragment cache
  was destroyed from the per-dispatch destructor on a worker thread,
  which crashed the resolver as soon as it used TCP in QBF mode.  Both
  caches are now torn down from `shutdown_server()` on the main loop.

### 1-RTT mode

In RAW mode the resolver sends speculative OPCODE 7 fragment requests
together with the query, so a fragmented answer completes in a single
round trip instead of two.  How many: as many as the last fragmented
answer from that server needed for the same query type (else for any
type), never fewer than the default of 4, which is also used for
servers without history.  `e2e/tools/txtimeline.py` prints every
exchange with a verdict line, e.g. (`example.test DNSKEY`, 4 fragments):

```
t=+0.0 ms  resolver -> auth   QUERY
t=+0.0 ms  resolver -> auth   FRAG REQUEST 1/4
t=+0.0 ms  resolver -> auth   FRAG REQUEST 2/4
t=+0.0 ms  resolver -> auth   FRAG REQUEST 3/4
t=+0.2 ms  auth -> resolver   FRAG REPLY   0/4
t=+0.3 ms  auth -> resolver   FRAG REPLY   1/4
t=+0.3 ms  auth -> resolver   FRAG REPLY   2/4
t=+0.3 ms  auth -> resolver   FRAG REPLY   3/4
=> 1 round trip: every fragment request left before the first reply arrived
```

`e2e/tools/check1rtt.py` counts an exchange as 1-RTT only if *every*
fragment request left before the first reply (by capture order, as the
timestamps only have 0.1 ms resolution).  It counts all exchanges with
the authoritative server: the resolver's and `dig`'s direct queries.

Before and after the October 1-RTT rework, same test bed and tools
(exchanges with the authoritative server completed in one round trip):

| algorithm | first 1-RTT version (September) | current |
| --------- | ------------------------------- | ------- |
| P256_FALCON512 | 14 of 17 | 17 of 17 |
| SLHDSASHA2128S (SPHINCS+) | 0 of 20 | 16 of 20 |
| FALCON1024 | 15 of 20 | 19 of 20 |

The September version capped the burst at 4 fragments (so 7-21
fragment answers always needed a second round trip) and built its
requests after the query had left (on a busy resolver some left after
fragment 0 arrived).  `dig` then fetched fragments one per round trip;
it now uses the same 1-RTT scheme as the resolver.

How the edge cases are handled:

* **Estimate too high** (or the answer is not fragmented): the server
  answers the extra requests with small OPCODE 7 error echoes, which the
  resolver ignores.  This is why the default is also the floor: an extra
  request costs a ~50-byte packet and a ~23-byte echo, a missing one
  costs a round trip.
* **Estimate too low**: the remaining fragments are requested in one
  burst when fragment 0 arrives (two round trips; the next query of that
  type is estimated from this answer).
* **Request overtakes the answer**: a speculative request can reach the
  server before the answer exists - always the case when the server is
  a recursive resolver that still has to resolve the name (e.g. `dig`
  asking the resolver).  It misses the server's fragment cache and is
  echoed.  The client counts echoes: more echoes than the estimate
  explains means requests were lost to this race, and it requests the
  missing fragments again as soon as one fragment tells it the size.
* **Server without fragmentation support**: every speculative request is
  echoed with NOTIMP and ignored; resolution proceeds exactly as stock
  BIND (interop scenario above).  The cost is three extra ~50-byte
  requests (and their echoes) per signed query to such a server; no
  "does not fragment" history is kept yet.
* Requests are only sent for queries with EDNS and the DO bit (unsigned
  answers never fragment).  The requests are built before the query is
  sent, so query and requests leave back to back.

Two problems found while verifying 1-RTT, both fixed:

* Requests were originally built after the query had been sent (by
  parsing and re-rendering the query), which on a busy resolver let
  fragment 0 arrive first.  They are now built from the query bytes
  directly (`raw_build_request()`, verified byte-identical to the
  renderer by `raw_test`) before the query is sent.
* A netmgr bug lost datagrams that arrived while a burst of requests was
  still being sent on the same socket: `isc__nm_start_reading()` skipped
  restarting the UDP receiver because libuv reports a handle with queued
  sends as active.  It affected `dig` (a client socket that stops
  reading after each datagram); fixed in `lib/isc/netmgr/netmgr.c`.
  A/B check with the final code and SPHINCS+ (20 `dig` queries each):
  fix reverted 0/20 direct and 11/20 through the resolver, fix in place
  20/20 and 20/20.

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
