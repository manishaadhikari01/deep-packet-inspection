"""Network protocol parsing for Ethernet, IPv4, TCP, and UDP."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from dpi.pcap_reader import RawPacket
from dpi.types import format_ip


class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17


class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806


@dataclass(slots=True)
class ParsedPacket:
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    payload_length: int = 0
    payload_offset: int = 0


def mac_to_string(mac: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in mac)


def protocol_to_string(protocol: int) -> str:
    if protocol == Protocol.ICMP:
        return "ICMP"
    if protocol == Protocol.TCP:
        return "TCP"
    if protocol == Protocol.UDP:
        return "UDP"
    return f"Unknown({protocol})"


def tcp_flags_to_string(flags: int) -> str:
    parts = []
    if flags & TCPFlags.SYN:
        parts.append("SYN")
    if flags & TCPFlags.ACK:
        parts.append("ACK")
    if flags & TCPFlags.FIN:
        parts.append("FIN")
    if flags & TCPFlags.RST:
        parts.append("RST")
    if flags & TCPFlags.PSH:
        parts.append("PSH")
    if flags & TCPFlags.URG:
        parts.append("URG")
    return " ".join(parts) if parts else "none"


def parse(raw: RawPacket) -> ParsedPacket | None:
    parsed = ParsedPacket(
        timestamp_sec=raw.header.ts_sec,
        timestamp_usec=raw.header.ts_usec,
    )

    data = raw.data
    length = len(data)
    offset = 0

    if length < 14:
        return None

    parsed.dest_mac = mac_to_string(data[0:6])
    parsed.src_mac = mac_to_string(data[6:12])
    parsed.ether_type = struct.unpack("!H", data[12:14])[0]
    offset = 14

    if parsed.ether_type != EtherType.IPv4:
        parsed.payload_offset = offset
        parsed.payload_length = max(0, length - offset)
        return parsed

    if length < offset + 20:
        return None

    ip_data = data[offset:]
    version_ihl = ip_data[0]
    parsed.ip_version = (version_ihl >> 4) & 0x0F
    ihl = version_ihl & 0x0F
    if parsed.ip_version != 4:
        return None

    ip_header_len = ihl * 4
    if ip_header_len < 20 or length < offset + ip_header_len:
        return None

    parsed.ttl = ip_data[8]
    parsed.protocol = ip_data[9]
    parsed.src_ip = format_ip(struct.unpack("<I", ip_data[12:16])[0])
    parsed.dest_ip = format_ip(struct.unpack("<I", ip_data[16:20])[0])
    parsed.has_ip = True
    offset += ip_header_len

    if parsed.protocol == Protocol.TCP:
        if length < offset + 20:
            return None
        tcp_data = data[offset:]
        parsed.src_port = struct.unpack("!H", tcp_data[0:2])[0]
        parsed.dest_port = struct.unpack("!H", tcp_data[2:4])[0]
        parsed.seq_number = struct.unpack("!I", tcp_data[4:8])[0]
        parsed.ack_number = struct.unpack("!I", tcp_data[8:12])[0]
        data_offset = (tcp_data[12] >> 4) & 0x0F
        tcp_header_len = data_offset * 4
        parsed.tcp_flags = tcp_data[13]
        if tcp_header_len < 20 or length < offset + tcp_header_len:
            return None
        parsed.has_tcp = True
        offset += tcp_header_len
    elif parsed.protocol == Protocol.UDP:
        if length < offset + 8:
            return None
        udp_data = data[offset:]
        parsed.src_port = struct.unpack("!H", udp_data[0:2])[0]
        parsed.dest_port = struct.unpack("!H", udp_data[2:4])[0]
        parsed.has_udp = True
        offset += 8

    parsed.payload_offset = offset
    parsed.payload_length = max(0, length - offset)
    return parsed


def payload_slice(raw: RawPacket, parsed: ParsedPacket) -> bytes:
    if parsed.payload_length <= 0:
        return b""
    return raw.data[parsed.payload_offset : parsed.payload_offset + parsed.payload_length]
