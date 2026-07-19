"""Multi-threaded DPI engine."""

from __future__ import annotations

import queue
import threading
import time
from collections import defaultdict
from dataclasses import dataclass

from dpi.packet_parser import parse
from dpi.pcap_reader import PcapPacketHeader, PcapReader, PcapWriter
from dpi.rules import BlockingRules
from dpi.sni_extractor import HTTPHostExtractor, SNIExtractor
from dpi.report import footer, row, section
from dpi.types import (
    AppType,
    FiveTuple,
    app_type_to_string,
    five_tuple_hash,
    parse_ip,
    sni_to_app_type,
)


@dataclass(slots=True)
class Packet:
    packet_id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    tcp_flags: int
    payload_offset: int
    payload_length: int


@dataclass
class FlowEntry:
    tuple: FiveTuple | None = None
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False


class TSQueue:
    def __init__(self, max_size: int = 10000) -> None:
        self._queue: queue.Queue[Packet | None] = queue.Queue(maxsize=max_size)
        self._shutdown = False

    def push(self, item: Packet) -> None:
        if self._shutdown:
            return
        while not self._shutdown:
            try:
                self._queue.put(item, timeout=0.1)
                return
            except queue.Full:
                continue

    def pop(self, timeout: float = 0.1) -> Packet | None:
        if self._shutdown and self._queue.empty():
            return None
        try:
            item = self._queue.get(timeout=timeout)
            return item
        except queue.Empty:
            return None

    def shutdown(self) -> None:
        self._shutdown = True

    def size(self) -> int:
        return self._queue.qsize()


class Stats:
    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded = 0
        self.dropped = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self._mutex = threading.Lock()
        self.app_counts: dict[AppType, int] = defaultdict(int)
        self.detected_snis: dict[str, AppType] = {}

    def record_app(self, app_type: AppType, sni: str) -> None:
        with self._mutex:
            self.app_counts[app_type] += 1
            if sni:
                self.detected_snis[sni] = app_type


class FastPath:
    def __init__(
        self,
        fp_id: int,
        rules: BlockingRules,
        stats: Stats,
        output_queue: TSQueue,
    ) -> None:
        self.id = fp_id
        self.rules = rules
        self.stats = stats
        self.output_queue = output_queue
        self.input_queue = TSQueue()
        self.flows: dict[FiveTuple, FlowEntry] = {}
        self._running = False
        self._thread: threading.Thread | None = None
        self.processed = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.shutdown()
        if self._thread is not None:
            self._thread.join()

    def _run(self) -> None:
        while self._running:
            packet = self.input_queue.pop(0.1)
            if packet is None:
                continue

            self.processed += 1
            flow = self.flows.setdefault(packet.tuple, FlowEntry())
            if flow.tuple is None:
                flow.tuple = packet.tuple
            flow.packets += 1
            flow.bytes += len(packet.data)

            if not flow.classified:
                self._classify_flow(packet, flow)

            if not flow.blocked:
                flow.blocked = self.rules.is_blocked(
                    packet.tuple.src_ip, flow.app_type, flow.sni
                )

            self.stats.record_app(flow.app_type, flow.sni)

            if flow.blocked:
                self.stats.dropped += 1
            else:
                self.stats.forwarded += 1
                self.output_queue.push(packet)

    @staticmethod
    def _classify_flow(packet: Packet, flow: FlowEntry) -> None:
        if packet.tuple.dst_port == 443 and packet.payload_length > 5:
            payload = packet.data[packet.payload_offset : packet.payload_offset + packet.payload_length]
            sni = SNIExtractor.extract(payload)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                flow.classified = True
                return

        if packet.tuple.dst_port == 80 and packet.payload_length > 10:
            payload = packet.data[packet.payload_offset : packet.payload_offset + packet.payload_length]
            host = HTTPHostExtractor.extract(payload)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return

        if packet.tuple.dst_port == 53 or packet.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        if packet.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif packet.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP


class LoadBalancer:
    def __init__(self, lb_id: int, fast_paths: list[FastPath]) -> None:
        self.id = lb_id
        self.fast_paths = fast_paths
        self.input_queue = TSQueue()
        self._running = False
        self._thread: threading.Thread | None = None
        self.dispatched = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.shutdown()
        if self._thread is not None:
            self._thread.join()

    def _run(self) -> None:
        while self._running:
            packet = self.input_queue.pop(0.1)
            if packet is None:
                continue

            fp_idx = five_tuple_hash(packet.tuple) % len(self.fast_paths)
            self.fast_paths[fp_idx].input_queue.push(packet)
            self.dispatched += 1


@dataclass
class DPIEngineConfig:
    num_lbs: int = 2
    fps_per_lb: int = 2


class DPIEngine:
    def __init__(self, config: DPIEngineConfig | None = None) -> None:
        self.config = config or DPIEngineConfig()
        self.rules = BlockingRules()
        self.stats = Stats()
        self.output_queue = TSQueue()

        total_fps = self.config.num_lbs * self.config.fps_per_lb
        print()
        section("DPI ENGINE v2.0 (Multi-threaded, Python)")
        row(
            "Load Balancers: ",
            f"{self.config.num_lbs:>2}    FPs per LB: {self.config.fps_per_lb:>2}    Total FPs: {total_fps:>2}",
        )
        footer()
        print()

        self.fast_paths = [
            FastPath(index, self.rules, self.stats, self.output_queue)
            for index in range(total_fps)
        ]
        self.load_balancers: list[LoadBalancer] = []
        for lb in range(self.config.num_lbs):
            start = lb * self.config.fps_per_lb
            lb_fps = self.fast_paths[start : start + self.config.fps_per_lb]
            self.load_balancers.append(LoadBalancer(lb, lb_fps))

    def block_ip(self, ip: str) -> None:
        self.rules.block_ip(ip)

    def block_app(self, app: str) -> None:
        self.rules.block_app(app)

    def block_domain(self, domain: str) -> None:
        self.rules.block_domain(domain)

    def process(self, input_file: str, output_file: str) -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        writer = PcapWriter(output_file, reader.global_header)

        for fp in self.fast_paths:
            fp.start()
        for lb in self.load_balancers:
            lb.start()

        output_running = threading.Event()
        output_running.set()

        def output_thread() -> None:
            while output_running.is_set() or self.output_queue.size() > 0:
                packet = self.output_queue.pop(0.05)
                if packet is None:
                    continue
                writer.write_packet(
                    PcapPacketHeader(
                        packet.ts_sec,
                        packet.ts_usec,
                        len(packet.data),
                        len(packet.data),
                    ),
                    packet.data,
                )

        writer_thread = threading.Thread(target=output_thread, daemon=True)
        writer_thread.start()

        print("[Reader] Processing packets...")
        packet_id = 0

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            parsed = parse(raw)
            if parsed is None or not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            packet = Packet(
                packet_id=packet_id,
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
                tuple=FiveTuple(
                    src_ip=parse_ip(parsed.src_ip),
                    dst_ip=parse_ip(parsed.dest_ip),
                    src_port=parsed.src_port,
                    dst_port=parsed.dest_port,
                    protocol=parsed.protocol,
                ),
                data=raw.data,
                tcp_flags=parsed.tcp_flags,
                payload_offset=parsed.payload_offset,
                payload_length=parsed.payload_length,
            )

            self.stats.total_packets += 1
            self.stats.total_bytes += len(packet.data)
            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            elif parsed.has_udp:
                self.stats.udp_packets += 1

            lb_idx = five_tuple_hash(packet.tuple) % len(self.load_balancers)
            self.load_balancers[lb_idx].input_queue.push(packet)
            packet_id += 1

        print(f"[Reader] Done reading {packet_id} packets")
        reader.close()

        time.sleep(0.5)

        for lb in self.load_balancers:
            lb.stop()
        for fp in self.fast_paths:
            fp.stop()

        output_running.clear()
        self.output_queue.shutdown()
        writer_thread.join()

        writer.close()
        self._print_report()
        print(f"\nOutput written to: {output_file}")
        return True

    def _print_report(self) -> None:
        print()
        section("PROCESSING REPORT")
        row("Total Packets:      ", f"{self.stats.total_packets:>12}")
        row("Total Bytes:        ", f"{self.stats.total_bytes:>12}")
        row("TCP Packets:        ", f"{self.stats.tcp_packets:>12}")
        row("UDP Packets:        ", f"{self.stats.udp_packets:>12}")
        section("FORWARD / DROP")
        row("Forwarded:          ", f"{self.stats.forwarded:>12}")
        row("Dropped:            ", f"{self.stats.dropped:>12}")
        section("THREAD STATISTICS")
        for index, lb in enumerate(self.load_balancers):
            row(f"  LB{index} dispatched:   ", f"{lb.dispatched:>12}")
        for index, fp in enumerate(self.fast_paths):
            row(f"  FP{index} processed:    ", f"{fp.processed:>12}")
        section("APPLICATION BREAKDOWN")

        sorted_apps = sorted(
            self.stats.app_counts.items(), key=lambda item: item[1], reverse=True
        )
        total = self.stats.total_packets
        for app_type, count in sorted_apps:
            pct = 100.0 * count / total if total else 0
            bar = "#" * int(pct / 5)
            row(
                f"{app_type_to_string(app_type):<15} {count:>8} {pct:5.1f}% ",
                bar,
            )

        footer()

        if self.stats.detected_snis:
            print("\n[Detected Domains/SNIs]")
            for sni, app_type in sorted(self.stats.detected_snis.items()):
                print(f"  - {sni} -> {app_type_to_string(app_type)}")
