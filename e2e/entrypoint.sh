#!/bin/bash
# Container entrypoint for the UDP fragmentation end-to-end test bed.
#
#   ROLE=auth      generate PQC keys, sign the zones, publish the root
#                  trust anchor in /shared and run an authoritative named
#   ROLE=resolver  wait for the trust anchor and run a validating resolver
#
# Environment: ALG (auth), UDP_FRAGMENTATION (RAW|QBF|none),
#              DNSSEC_VALIDATION (resolver), DEBUG_LEVEL
set -euo pipefail

ROLE="${ROLE:-auth}"
ALG="${ALG:-P256_FALCON512}"
MODE="${UDP_FRAGMENTATION:-RAW}"
DEBUG_LEVEL="${DEBUG_LEVEL:-3}"
E2E=/src/e2e
CONF=/etc/bind/named.conf
WORK=/var/cache/bind

frag_clause() {
	case "$MODE" in
	RAW | QBF) echo "udp-fragmentation $MODE;" ;;
	*) echo "" ;;
	esac
}

cookie_clause() {
	# QBF's reassembled replies do not carry a valid server COOKIE, so a
	# cookie-aware resolver re-fetches them over TCP (anti-spoofing).
	# The reference QBF setup ran without DNS cookies (its capture has no
	# COOKIE options at all), so QBF mode does the same.  RAW reassembles
	# the original bytes including the cookie and needs no exception.
	case "$MODE" in
	QBF) echo "send-cookie no;" ;;
	*) echo "" ;;
	esac
}

sign_zone() {
	# sign_zone <zone> <zonefile>  -> <zonefile>.signed, prints DS records
	local zone="$1" file="$2"
	dnssec-keygen -q -a "$ALG" -K "$WORK/keys" -f KSK "$zone" >/dev/null
	dnssec-keygen -q -a "$ALG" -K "$WORK/keys" "$zone" >/dev/null
	dnssec-signzone -q -S -K "$WORK/keys" -o "$zone" -f "$file.signed" "$file" >/dev/null
	# this fork's dnssec tools print diagnostics on stdout: keep DS lines only
	dnssec-dsfromkey -f "$file.signed" "$zone" 2>/dev/null |
		grep -E '[[:space:]]DS[[:space:]]'
}

case "$ROLE" in
auth)
	rm -rf "$WORK"/* && mkdir -p "$WORK/keys"
	cp "$E2E/auth/zones/"db.* "$WORK/"
	cd "$WORK"

	echo "== signing zones with $ALG =="
	sign_zone example.test db.example.test >>db.test
	sign_zone test db.test >>db.root
	sign_zone . db.root >/dev/null

	# root KSK -> trust anchor for the resolver
	ksk=$(grep -l 'This is a key-signing key' keys/K.+*.key | head -1)
	awk '{
		for (k = 1; k <= NF; k++) if ($k == "DNSKEY") break;
		if (k > NF || $(k + 1) != "257") next;
		printf "trust-anchors {\n\t. static-key %s %s %s \"", $(k + 1), $(k + 2), $(k + 3);
		for (i = k + 4; i <= NF; i++) printf "%s", $i;
		print "\";\n};" }' "$ksk" >/shared/trust-anchors.conf
	echo "== trust anchor =="
	cat /shared/trust-anchors.conf

	sed -e "s|@FRAG@|$(frag_clause)|" "$E2E/auth/named.conf.tmpl" >"$CONF"
	named-checkconf "$CONF"
	for z in db.root.signed db.test.signed db.example.test.signed; do
		ls -la "$z"
	done
	echo "== starting authoritative named (mode: $MODE, alg: $ALG) =="
	exec named -g -c "$CONF" -d "$DEBUG_LEVEL"
	;;
resolver)
	for i in $(seq 1 60); do
		[ -s /shared/trust-anchors.conf ] && break
		sleep 1
	done
	[ -s /shared/trust-anchors.conf ] || { echo "no trust anchor from auth"; exit 1; }
	mkdir -p "$WORK"
	sed -e "s|@FRAG@|$(frag_clause)|" \
		-e "s|@COOKIE@|$(cookie_clause)|" \
		-e "s|@VALIDATION@|${DNSSEC_VALIDATION:-yes}|" \
		"$E2E/resolver/named.conf.tmpl" >"$CONF"
	cat /shared/trust-anchors.conf >>"$CONF"
	cp "$E2E/resolver/root.hints" "$WORK/root.hints"
	named-checkconf "$CONF"
	echo "== starting resolver named (mode: $MODE, validation: ${DNSSEC_VALIDATION:-yes}) =="
	exec named -g -c "$CONF" -d "$DEBUG_LEVEL"
	;;
*)
	exec "$@"
	;;
esac
