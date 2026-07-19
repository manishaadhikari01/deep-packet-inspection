"""PCAP file reader and writer."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1


@dataclass(slots=True)
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass(slots=True)
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass(slots=True)
class RawPacket:
    header: PcapPacketHeader
    data: bytes


class PcapReader:
    def __init__(self) -> None:
        self._file: BinaryIO | None = None
        self.global_header = PcapGlobalHeader(0, 0, 0, 0, 0, 0, 0)
        self._needs_byte_swap = False
        self._endian = "<"

    def open(self, filename: str | Path) -> bool:
        self.close()
        try:
            self._file = open(filename, "rb")
        except OSError as exc:
            print(f"Error: Could not open file: {filename}")
            print(exc)
            return False

        header_bytes = self._file.read(24)
        if len(header_bytes) != 24:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        magic = struct.unpack("<I", header_bytes[:4])[0]
        if magic == PCAP_MAGIC_NATIVE:
            self._needs_byte_swap = False
            self._endian = "<"
        elif magic == PCAP_MAGIC_SWAPPED:
            self._needs_byte_swap = True
            self._endian = ">"
        else:
            print(f"Error: Invalid PCAP magic number: 0x{magic:08x}")
            self.close()
            return False

        (
            self.global_header.magic_number,
            self.global_header.version_major,
            self.global_header.version_minor,
            self.global_header.thiszone,
            self.global_header.sigfigs,
            self.global_header.snaplen,
            self.global_header.network,
        ) = struct.unpack(f"{self._endian}IHHIIII", header_bytes)

        print(f"Opened PCAP file: {filename}")
        print(
            f"  Version: {self.global_header.version_major}.{self.global_header.version_minor}"
        )
        print(f"  Snaplen: {self.global_header.snaplen} bytes")
        link_type = self.global_header.network
        suffix = " (Ethernet)" if link_type == 1 else ""
        print(f"  Link type: {link_type}{suffix}")
        return True

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
        self._needs_byte_swap = False

    @property
    def is_open(self) -> bool:
        return self._file is not None

    def read_next_packet(self) -> RawPacket | None:
        if self._file is None:
            return None

        header_bytes = self._file.read(16)
        if not header_bytes:
            return None
        if len(header_bytes) != 16:
            print("Error: Could not read packet header")
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{self._endian}IIII", header_bytes
        )

        if incl_len > self.global_header.snaplen or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}")
            return None

        data = self._file.read(incl_len)
        if len(data) != incl_len:
            print("Error: Could not read packet data")
            return None

        return RawPacket(
            header=PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len),
            data=data,
        )

    def __enter__(self) -> PcapReader:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class PcapWriter:
    def __init__(self, filename: str | Path, global_header: PcapGlobalHeader | None = None) -> None:
        self._file = open(filename, "wb")
        header = global_header or PcapGlobalHeader(
            PCAP_MAGIC_NATIVE, 2, 4, 0, 0, 65535, 1
        )
        self._file.write(
            struct.pack(
                "<IHHIIII",
                header.magic_number,
                header.version_major,
                header.version_minor,
                header.thiszone,
                header.sigfigs,
                header.snaplen,
                header.network,
            )
        )

    def write_packet(self, header: PcapPacketHeader, data: bytes) -> None:
        incl_len = len(data)
        self._file.write(
            struct.pack(
                "<IIII",
                header.ts_sec,
                header.ts_usec,
                incl_len,
                header.orig_len or incl_len,
            )
        )
        self._file.write(data)

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
