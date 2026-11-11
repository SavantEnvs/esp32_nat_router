#!/usr/bin/env bash
#
# mayhem/build.sh — host build of the ESP32 NAT router's packet-path code.
#
# The firmware targets ESP-IDF, which cannot run under a fuzzer. The upstream C sources that parse
# attacker-controlled bytes (components/acl/acl.c, components/pcap_capture/*.c, main/netif_hooks.c)
# are compiled UNMODIFIED against thin ESP-IDF/FreeRTOS shims (mayhem/shim) and the real lwIP 2.2.1
# headers/sources pre-fetched into /opt/toolchains/deps (see mayhem/Dockerfile).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

LWIP=/opt/toolchains/deps/lwip-2.2.1/src
[ -d "$LWIP/src/include" ] || { echo "lwIP not found at $LWIP" >&2; exit 1; }

B="$SRC/build_mayhem"          # ignored by upstream's `build_*/**` rule, so `git clean -ffdX` removes it
rm -rf "$B"
mkdir -p "$B/san" "$B/plain"

INC=(-I"$SRC/mayhem/shim" -I"$LWIP/src/include" -I"$SRC/include" -I"$SRC/main"
     -I"$SRC/components/acl/include" -I"$SRC/components/pcap_capture"
     -I"$SRC/components/pcap_capture/include")

# The project's dependencies: unmodified upstream sources plus the lwIP files they call into.
DEPS=(components/acl/acl.c components/pcap_capture/pcap_ringbuf.c
      "$LWIP/src/core/ipv4/ip4_addr.c" "$LWIP/src/core/inet_chksum.c" "$LWIP/src/core/def.c")

obj() { echo "$1/$(basename "${2%.*}").o"; }

# 1) sanitized + SanCov-instrumented objects for the fuzz targets.
#    netif_hooks.c reads the TCP MSS option through a misaligned uint16_t* (clamp_tcp_mss); that
#    alignment report would halt every run on its first SYN, so it is relaxed on the harness TU that
#    includes it (-fno-sanitize=alignment); every other check stays on.
SAN=($SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link)
for f in "${DEPS[@]}" mayhem/pcap_wrap.c; do
  $CC "${SAN[@]}" "${INC[@]}" -c "$f" -o "$(obj "$B/san" "$f")"
done
$CC "${SAN[@]}" -fno-sanitize=alignment "${INC[@]}" -c mayhem/fuzz_netif_hooks.c -o "$B/san/fuzz_netif_hooks.o"
for t in fuzz_acl_parse fuzz_pcap_ringbuf; do
  $CC "${SAN[@]}" "${INC[@]}" -c "mayhem/$t.c" -o "$B/san/$t.o"
done
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/san/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/san/standalone_main.o"

link_deps() { # <netif|acl|ring>
  case "$1" in
    netif) echo "$(obj "$B/san" pcap_wrap.c) $(obj "$B/san" components/acl/acl.c) $(obj "$B/san" components/pcap_capture/pcap_ringbuf.c) $(obj "$B/san" ip4_addr.c) $(obj "$B/san" inet_chksum.c) $(obj "$B/san" def.c)" ;;
    acl)   echo "$(obj "$B/san" components/acl/acl.c) $(obj "$B/san" ip4_addr.c) $(obj "$B/san" def.c)" ;;
    ring)  echo "$(obj "$B/san" components/pcap_capture/pcap_ringbuf.c)" ;;
  esac
}

link_target() { # <name> <depskey>
  local name="$1" deps; deps="$(link_deps "$2")"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/san/$name.o" $deps "$B/san/lsan_off.o" -o "$SRC/$name"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/san/$name.o" $deps "$B/san/lsan_off.o" "$B/san/standalone_main.o" -o "$SRC/$name-standalone"
}
link_target fuzz_netif_hooks netif
link_target fuzz_acl_parse acl
link_target fuzz_pcap_ringbuf ring

# 2) known-answer test binary with the project's normal flags (no sanitizers, no SanCov).
PLAIN=(-O2 $COVERAGE_FLAGS)
for f in "${DEPS[@]}" mayhem/pcap_wrap.c; do
  $CC "${PLAIN[@]}" "${INC[@]}" -c "$f" -o "$(obj "$B/plain" "$f")"
done
$CC "${PLAIN[@]}" "${INC[@]}" -c mayhem/kat.c -o "$B/plain/kat.o"
$CC "${PLAIN[@]}" "$B"/plain/*.o -o "$SRC/esp32_nat_kat"
