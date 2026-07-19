"""Single-threaded DPI engine."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from dpi.packet_parser import parse, payload_slice
from dpi.pcap_reader import PcapPacketHeader, PcapReader, PcapWriter
from dpi.rules import BlockingRules
from dpi.sni_extractor import HTTPHostExtractor, SNIExtractor
from dpi.report import banner, footer, row, section
from dpi.types import AppType, FiveTuple, app_type_to_string, parse_ip, sni_to_app_type


@dataclass
class Flow:
    tuple: FiveTuple | None = None
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


class SimpleDPIEngine:
    def __init__(self, rules: BlockingRules | None = None) -> None:
        self.rules = rules or BlockingRules()

    def process(self, input_file: str, output_file: str) -> bool:
        banner("DPI ENGINE v1.0 (Python)")

        reader = PcapReader()
        if not reader.open(input_file):
            return False

        writer = PcapWriter(output_file, reader.global_header)

        flows: dict[FiveTuple, Flow] = {}
        total_packets = 0
        forwarded = 0
        dropped = 0
        app_stats: dict[AppType, int] = defaultdict(int)

        print("[DPI] Processing packets...")

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            total_packets += 1
            parsed = parse(raw)
            if parsed is None or not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            tuple_ = FiveTuple(
                src_ip=parse_ip(parsed.src_ip),
                dst_ip=parse_ip(parsed.dest_ip),
                src_port=parsed.src_port,
                dst_port=parsed.dest_port,
                protocol=parsed.protocol,
            )

            flow = flows.setdefault(tuple_, Flow())
            if flow.tuple is None:
                flow.tuple = tuple_
            flow.packets += 1
            flow.bytes += len(raw.data)

            payload = payload_slice(raw, parsed)

            if (
                flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)
                and not flow.sni
                and parsed.has_tcp
                and parsed.dest_port == 443
                and len(payload) > 5
            ):
                sni = SNIExtractor.extract(payload)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)

            if (
                flow.app_type in (AppType.UNKNOWN, AppType.HTTP)
                and not flow.sni
                and parsed.has_tcp
                and parsed.dest_port == 80
            ):
                host = HTTPHostExtractor.extract(payload)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)

            if flow.app_type == AppType.UNKNOWN and (
                parsed.dest_port == 53 or parsed.src_port == 53
            ):
                flow.app_type = AppType.DNS

            if flow.app_type == AppType.UNKNOWN:
                if parsed.dest_port == 443:
                    flow.app_type = AppType.HTTPS
                elif parsed.dest_port == 80:
                    flow.app_type = AppType.HTTP

            if not flow.blocked:
                flow.blocked = self.rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni)
                if flow.blocked:
                    print(
                        f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} "
                        f"({app_type_to_string(flow.app_type)}"
                        f"{': ' + flow.sni if flow.sni else ''})"
                    )

            app_stats[flow.app_type] += 1

            if flow.blocked:
                dropped += 1
            else:
                forwarded += 1
                writer.write_packet(
                    PcapPacketHeader(
                        raw.header.ts_sec,
                        raw.header.ts_usec,
                        len(raw.data),
                        raw.header.orig_len,
                    ),
                    raw.data,
                )

        reader.close()
        writer.close()

        self._print_report(total_packets, forwarded, dropped, flows, app_stats)
        print(f"\nOutput written to: {output_file}")
        return True

    @staticmethod
    def _print_report(
        total_packets: int,
        forwarded: int,
        dropped: int,
        flows: dict[FiveTuple, Flow],
        app_stats: dict[AppType, int],
    ) -> None:
        print()
        section("PROCESSING REPORT")
        row("Total Packets:      ", f"{total_packets:>10}")
        row("Forwarded:          ", f"{forwarded:>10}")
        row("Dropped:            ", f"{dropped:>10}")
        row("Active Flows:       ", f"{len(flows):>10}")
        section("APPLICATION BREAKDOWN")

        sorted_apps = sorted(app_stats.items(), key=lambda item: item[1], reverse=True)
        for app_type, count in sorted_apps:
            pct = 100.0 * count / total_packets if total_packets else 0
            bar = "#" * int(pct / 5)
            row(
                f"{app_type_to_string(app_type):<15} {count:>8} {pct:5.1f}% ",
                bar,
            )

        footer()

        unique_snis: dict[str, AppType] = {}
        for flow in flows.values():
            if flow.sni:
                unique_snis[flow.sni] = flow.app_type

        if unique_snis:
            print("\n[Detected Applications/Domains]")
            for sni, app_type in sorted(unique_snis.items()):
                print(f"  - {sni} -> {app_type_to_string(app_type)}")
