"""Command-line interface for the DPI engine."""

from __future__ import annotations

import argparse
import sys

from dpi.engine import DPIEngine, DPIEngineConfig
from dpi.rules import BlockingRules
from dpi.simple_engine import SimpleDPIEngine


USAGE = """
DPI Engine - Deep Packet Inspection System (Python)
====================================================

Usage:
  python -m dpi <input.pcap> <output.pcap> [options]
  python -m dpi.simple <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --simple               Use single-threaded engine (default: multi-threaded)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)

Examples:
  python -m dpi test_dpi.pcap output.pcap --block-app YouTube
  python -m dpi test_dpi.pcap output.pcap --simple
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deep Packet Inspection engine for PCAP files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE,
    )
    parser.add_argument("input_pcap", help="Input PCAP file")
    parser.add_argument("output_pcap", help="Output PCAP file")
    parser.add_argument("--block-ip", action="append", default=[], metavar="IP")
    parser.add_argument("--block-app", action="append", default=[], metavar="APP")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOM")
    parser.add_argument("--simple", action="store_true", help="Use single-threaded engine")
    parser.add_argument("--lbs", type=int, default=2, help="Load balancer thread count")
    parser.add_argument("--fps", type=int, default=2, help="Fast path threads per LB")
    return parser


def apply_rules(
    rules: BlockingRules,
    block_ips: list[str],
    block_apps: list[str],
    block_domains: list[str],
) -> None:
    for ip in block_ips:
        rules.block_ip(ip)
    for app in block_apps:
        rules.block_app(app)
    for domain in block_domains:
        rules.block_domain(domain)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.simple:
        rules = BlockingRules()
        apply_rules(rules, args.block_ip, args.block_app, args.block_domain)
        engine = SimpleDPIEngine(rules)
        success = engine.process(args.input_pcap, args.output_pcap)
    else:
        config = DPIEngineConfig(num_lbs=args.lbs, fps_per_lb=args.fps)
        engine = DPIEngine(config)
        apply_rules(engine.rules, args.block_ip, args.block_app, args.block_domain)
        success = engine.process(args.input_pcap, args.output_pcap)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
