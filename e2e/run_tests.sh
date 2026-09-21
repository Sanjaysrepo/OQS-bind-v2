#!/usr/bin/env bash
# End-to-end test of UDP fragmentation (RAW or QBF) with PQC-signed zones.
#
#   e2e/run_tests.sh [ALG] [MODE] [DNSSEC_VALIDATION]
#     ALG   dnssec-keygen algorithm name, e.g. P256_FALCON512 (default),
#           FALCON512, FALCON1024, MLDSA44, SLHDSASHA2128S, MAYO1, SNOVA2454
#     MODE  RAW (default) | QBF | none
#
# Needs docker with the compose plugin and the oqs-bind-deps image
# (see Dockerfile.deps).  Produces captures/<MODE>_<ALG>.pcap and
# results/<MODE>_<ALG>/*.txt and prints a PASS/FAIL table.
set -uo pipefail
cd "$(dirname "$0")"

ALG="${1:-P256_FALCON512}"
MODE="${2:-RAW}"
VALIDATION="${3:-yes}"
# optional 4th argument: a different mode for the authoritative server,
# e.g. `run_tests.sh P256_FALCON512 RAW yes none` tests a RAW resolver
# against a server without fragmentation support (interoperability).
AUTH_MODE="${4:-$MODE}"
TAG="${MODE}_${ALG}"
[ "$AUTH_MODE" != "$MODE" ] && TAG="${MODE}-auth${AUTH_MODE}_${ALG}"
OUT="results/$TAG"
PCAP="captures/$TAG.pcap"
export ALG DNSSEC_VALIDATION="$VALIDATION"
export UDP_FRAGMENTATION="$MODE" RESOLVER_FRAG="$MODE" AUTH_FRAG="$AUTH_MODE"
export DEBUG_LEVEL="${DEBUG_LEVEL:-3}"

compose() { docker compose "$@"; }
rexec() { docker compose exec -T resolver timeout 30 "$@"; }
aexec() { docker compose exec -T auth "$@"; }

pass=0; fail=0
declare -a REPORT
check() {
	# check <name> <ok:0/1> <detail>
	if [ "$2" = 0 ]; then pass=$((pass + 1)); REPORT+=("PASS  $1  $3"); else fail=$((fail + 1)); REPORT+=("FAIL  $1  $3"); fi
}

echo "==> building image (ALG=$ALG MODE=$MODE validation=$VALIDATION)"
compose build --quiet || { echo "build failed"; exit 1; }
mkdir -p "$OUT" captures
rm -f "$PCAP" "$OUT"/*.txt "$OUT"/*.log
compose down -v --remove-orphans >/dev/null 2>&1
compose up -d --force-recreate >/dev/null || { echo "compose up failed"; compose logs; exit 1; }

echo "==> waiting for the resolver"
ready=0
for i in $(seq 1 60); do
	out=$(rexec dig @127.0.0.1 . SOA +time=3 +tries=1 2>/dev/null)
	if grep -q "status: NOERROR" <<<"$out"; then ready=1; break; fi
	sleep 1
done
if [ $ready = 0 ]; then
	echo "resolver not ready"; compose logs --no-color >"$OUT/startup.log" 2>&1; compose logs --tail 30
	compose down -v >/dev/null; exit 1
fi

echo "==> capturing on the resolver"
rexec sh -c "tcpdump -i any -U -w /captures/$TAG.pcap port 53 >/dev/null 2>&1 &"
sleep 1

run_dig() {
	# run_dig <file> <dig args...>
	local file="$1"; shift
	rexec dig "$@" +dnssec +time=5 +tries=1 >"$OUT/$file.txt" 2>&1
}
status_of() { grep -o "status: [A-Z]*" "$OUT/$1.txt" | head -1 | cut -d' ' -f2; }
size_of() { grep -o "MSG SIZE  rcvd: [0-9]*" "$OUT/$1.txt" | grep -o "[0-9]*$"; }
flags_of() { grep -o "^;; flags:[^;]*" "$OUT/$1.txt" | head -1; }

# --- 1. plain A record through the resolver (three RRSIGs on the way) ---
run_dig r_test_A @127.0.0.1 test.example.test A
s=$(status_of r_test_A); [ "$s" = NOERROR ] && grep -q "^test.example.test.*IN.*A.*10.0.0.1" "$OUT/r_test_A.txt"
check "resolver: test.example.test A" $? "status=$s $(flags_of r_test_A)"
if [ "$VALIDATION" = yes ]; then
	grep -q "flags:.* ad" "$OUT/r_test_A.txt"
	check "resolver: answer validated (ad)" $? "$(flags_of r_test_A)"
fi

# --- 2. large DNSKEY responses through the resolver ---
for z in . test example.test; do
	n="r_dnskey_$(echo "$z" | tr . _)"
	run_dig "$n" @127.0.0.1 "$z" DNSKEY
	s=$(status_of "$n"); sz=$(size_of "$n")
	[ "$s" = NOERROR ] && grep -q "DNSKEY.257" "$OUT/$n.txt"
	check "resolver: $z DNSKEY" $? "status=$s size=$sz"
done

# --- 3. several names in a row (fragment cache under load) ---
ok=0
for i in 0 1 2 3 4 5 6 7 8 9; do
	run_dig "r_test${i}_A" @127.0.0.1 "test$i.example.test" A
	[ "$(status_of "r_test${i}_A")" = NOERROR ] && grep -q "10.0.0.1$i" "$OUT/r_test${i}_A.txt" && ok=$((ok + 1))
done
[ $ok = 10 ]; check "resolver: test0..9 A" $? "$ok/10 answered"

# --- 4. dig straight at the authoritative server over UDP (dig's own client) ---
run_dig a_dnskey_udp @172.30.0.10 example.test DNSKEY +norecurse +bufsize=1232
run_dig a_dnskey_tcp @172.30.0.10 example.test DNSKEY +norecurse +tcp
su=$(status_of a_dnskey_udp); st=$(status_of a_dnskey_tcp)
zu=$(size_of a_dnskey_udp); zt=$(size_of a_dnskey_tcp)
[ "$su" = NOERROR ] && [ "$zu" = "$zt" ] && ! grep -q "flags:.* tc" "$OUT/a_dnskey_udp.txt"
check "dig@auth: DNSKEY over UDP == TCP" $? "udp: status=$su size=$zu  tcp: status=$st size=$zt"
grep -c "RRSIG" "$OUT/a_dnskey_udp.txt" >/dev/null
run_dig a_test_A_udp @172.30.0.10 test.example.test A +norecurse +bufsize=1232
run_dig a_test_A_tcp @172.30.0.10 test.example.test A +norecurse +tcp
[ "$(status_of a_test_A_udp)" = NOERROR ] && [ "$(size_of a_test_A_udp)" = "$(size_of a_test_A_tcp)" ]
check "dig@auth: A over UDP == TCP" $? "udp=$(size_of a_test_A_udp) tcp=$(size_of a_test_A_tcp)"

# --- 5. a client without EDNS must still get a (truncated) answer ---
rexec dig @172.30.0.10 example.test DNSKEY +norecurse +noedns +ignore +time=5 +tries=1 >"$OUT/a_noedns.txt" 2>&1
# without EDNS there is no DO bit: the answer either fits in 512 bytes or is truncated
s=$(status_of a_noedns); z=$(size_of a_noedns)
[ "$s" = NOERROR ] && { grep -q "flags:.* tc" "$OUT/a_noedns.txt" || [ "${z:-999}" -le 512 ]; }
check "dig@auth: no EDNS -> TC or fits" $? "status=$s size=$z $(flags_of a_noedns)"

sleep 1
rexec pkill -INT tcpdump >/dev/null 2>&1; sleep 1
compose logs --no-color auth >"$OUT/auth.log" 2>&1
compose logs --no-color resolver >"$OUT/resolver.log" 2>&1
compose down -v >/dev/null 2>&1
compose logs --no-color >"$OUT/shutdown.log" 2>&1
! grep -qE "assertion failure|REQUIRE\(|INSIST\(" "$OUT/auth.log" "$OUT/resolver.log" "$OUT/shutdown.log"
check "named: no assertion failures (run + shutdown)" $? "$(grep -hoE "(auth|resolver) .*(REQUIRE|INSIST)\([^)]*\)" "$OUT"/*.log | head -1)"

echo "==> packet summary"
if [ -s "$PCAP" ]; then
	python3 tools/pcapdump.py "$PCAP" >"$OUT/pcap.txt" 2>&1 || python tools/pcapdump.py "$PCAP" >"$OUT/pcap.txt" 2>&1
	frags=$(grep -c "frag_nr" "$OUT/pcap.txt")
	reqs=$(grep -c "opcode=7" "$OUT/pcap.txt")
	tc=$(grep -c "tc=1" "$OUT/pcap.txt")
	tcp=$(grep -c " TCP " "$OUT/pcap.txt")
	echo "    fragment datagrams: $frags   opcode-7 requests: $reqs   TC=1: $tc   TCP packets: $tcp"
	if [ "$MODE" = RAW ] && [ "$AUTH_MODE" = RAW ]; then
		[ "$frags" -gt 0 ] && [ "$reqs" -gt 0 ]
		check "pcap: RAW fragments and requests seen" $? "frags=$frags reqs=$reqs"
		rtt=$(python3 tools/check1rtt.py "$OUT/pcap.txt" 2>/dev/null || python tools/check1rtt.py "$OUT/pcap.txt")
		echo "    $rtt"
		grep -qE "1-RTT \(speculative requests\): [1-9]" <<<"$rtt"
		check "pcap: 1-RTT speculative requests observed" $? "$rtt"
	fi
else
	echo "    (no capture)"
fi

echo
printf '%s\n' "${REPORT[@]}"
echo
echo "$pass passed, $fail failed  (results in $OUT, capture $PCAP)"
[ "$fail" = 0 ]
