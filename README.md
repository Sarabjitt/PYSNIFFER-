# pysniffer

A simple network packet sniffer written in pure Python (standard library only, no dependencies).

![tests](https://github.com/YOUR-USERNAME/pysniffer/actions/workflows/ci.yml/badge.svg)

It captures raw frames, decodes them layer by layer, filters them with a tcpdump-style expression language,
and saves/loads Wireshark-compatible `.pcap` files.

**Protocols:** Ethernet/VLAN · ARP · IPv4 · IPv6 · TCP · UDP · ICMP/ICMPv6 · DNS · HTTP · TLS (SNI)

## Quick start
```bash
python make_sample_pcap.py                    # creates a fake sample.pcap (no admin needed)
python -m pysniffer -r sample.pcap -s         # analyze it

sudo python3 -m pysniffer                     # live capture (Linux; Administrator on Windows)
sudo python3 -m pysniffer -f "tcp port 443" -w out.pcap
```
Requires Python 3.9+. Live capture needs root/Administrator and works on Linux and Windows; on macOS capture with
`tcpdump -w x.pcap` and analyze with `-r`.

## Options
`-i` interface · `-f` filter · `-c` count · `-t` seconds · `-w` write pcap · `-r` read pcap · `-v` detail ·
`-x` hex · `-A` ascii · `--json` · `-s` stats · `-q` quiet · `-L` list interfaces

**Filters:** `tcp udp icmp arp ip ip6 dns http tls syn fin rst`, `host/net/port` (with `src`/`dst`), `mac`, `vlan`,
`len > N`, `contains TEXT`, combined with `and or not ( )`.

## Project layout
```
pysniffer/  capture.py  protocols.py  filters.py  pcap.py  stats.py  cli.py
tests/      python -m unittest discover -s tests
```

## Roadmap
- [ ] Conversation (flow) tracking
- [ ] Learn mode: annotate every header field
- [ ] Attack detection (port scans, ARP spoofing, ...)
- [ ] Traffic simulator and pcap replay
- [ ] Live web dashboard

## Ethics
Only capture on networks you own or are authorised to monitor. Capture files can contain sensitive data.

## License
MIT
