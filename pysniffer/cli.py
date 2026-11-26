from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__
from .capture import CaptureError, list_interfaces, sniff
from .filters import FilterError, compile_filter
from .pcap import PcapReader, PcapWriter
from .protocols import hexdump, parse_packet
from .stats import Stats

COLORS = {"TCP": "36", "UDP": "34", "DNS": "33", "mDNS": "33", "HTTP": "32", "TLS": "35",
          "ARP": "93", "ICMP": "31", "ICMPv6": "31"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pysniffer", description="Simple network packet sniffer",
        epilog='filter examples: "tcp and port 443" | "host 10.0.0.5 and not dns" | "http or (udp and dst port 53)"')
    ap.add_argument("-i", "--interface", help="interface to capture on (default: all, Linux)")
    ap.add_argument("-f", "--filter", default="", help="filter expression")
    ap.add_argument("-c", "--count", type=int, default=0, help="stop after N matching packets")
    ap.add_argument("-t", "--duration", type=float, default=0, help="stop after N seconds")
    ap.add_argument("-w", "--write", metavar="FILE", help="save matching packets to a pcap file")
    ap.add_argument("-r", "--read", metavar="FILE", help="read packets from a pcap file instead of the network")
    ap.add_argument("-v", "--verbose", action="store_true", help="show layer-by-layer detail")
    ap.add_argument("-x", "--hex", action="store_true", help="hex dump of each packet")
    ap.add_argument("-A", "--ascii", action="store_true", help="print printable payload text")
    ap.add_argument("--json", action="store_true", help="output one JSON object per packet")
    ap.add_argument("-s", "--stats", action="store_true", help="print statistics at the end")
    ap.add_argument("-q", "--quiet", action="store_true", help="don't print packets (useful with -w/--stats)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--relative-time", action="store_true", help="timestamps relative to first packet")
    ap.add_argument("-L", "--list-interfaces", action="store_true")
    ap.add_argument("-V", "--version", action="version", version=f"pysniffer {__version__}")
    return ap


def _source(args):
    if args.read:
        r = PcapReader(args.read)
        for ts, data in r:
            yield ts, data, r.link
        r.close()
    else:
        yield from sniff(args.interface)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_interfaces:
        print("\n".join(list_interfaces()) or "(no interface list available on this platform)")
        return 0
    try:
        pred = compile_filter(args.filter)
    except FilterError as e:
        print(f"filter error: {e}", file=sys.stderr); return 2

    color = sys.stdout.isatty() and not args.no_color and not args.json
    stats, writer, n, t0, start = Stats(), None, 0, None, time.time()
    try:
        for ts, data, link in _source(args):
            if args.duration and time.time() - start >= args.duration:
                break
            if not data:
                continue
            if writer is None and args.write:
                writer = PcapWriter(args.write, link)
            p = parse_packet(data, ts, link)
            if not pred(p):
                continue
            n += 1
            t0 = t0 if t0 is not None else p.ts
            stats.add(p)
            if writer:
                writer.write(ts, data)
            if not args.quiet:
                _show(p, args, color, t0 if args.relative_time else None)
            if args.count and n >= args.count:
                break
    except KeyboardInterrupt:
        pass
    except (CaptureError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr); return 1
    finally:
        if writer:
            writer.close()
    if args.stats:
        print(stats.report(), file=sys.stderr if args.json else sys.stdout)
    print(f"\n{n} packet(s) matched" + (f", saved to {args.write}" if args.write else ""), file=sys.stderr)
    return 0


def _show(p, args, color, rel):
    if args.json:
        print(json.dumps(p.to_dict())); return
    text = p.detail() if args.verbose else p.summary(rel)
    if color and p.proto in COLORS:
        text = f"\033[{COLORS[p.proto]}m{text}\033[0m"
    print(text)
    if args.ascii and p.payload:
        s = "".join(chr(b) if 32 <= b < 127 or b in (10, 13, 9) else "." for b in p.payload)
        print("    " + s[:2000].replace("\r\n", "\n").replace("\n", "\n    "))
    if args.hex:
        print(hexdump(p.raw))
    sys.stdout.flush()
