"""Core data types for the DPI engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class AppType(Enum):
    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TLS = auto()
    QUIC = auto()
    GOOGLE = auto()
    FACEBOOK = auto()
    YOUTUBE = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    TIKTOK = auto()
    SPOTIFY = auto()
    ZOOM = auto()
    DISCORD = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()


_APP_TYPE_NAMES = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}

_NAME_TO_APP_TYPE = {name: app for app, name in _APP_TYPE_NAMES.items()}


@dataclass(frozen=True, slots=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> FiveTuple:
        return FiveTuple(
            self.dst_ip,
            self.src_ip,
            self.dst_port,
            self.src_port,
            self.protocol,
        )

    def to_string(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (
            f"{format_ip(self.src_ip)}:{self.src_port} -> "
            f"{format_ip(self.dst_ip)}:{self.dst_port} ({proto})"
        )


def format_ip(ip: int) -> str:
    return ".".join(str((ip >> (8 * i)) & 0xFF) for i in range(4))


def parse_ip(ip: str) -> int:
    result = 0
    octet = 0
    shift = 0
    for char in ip:
        if char == ".":
            result |= octet << shift
            shift += 8
            octet = 0
        elif char.isdigit():
            octet = octet * 10 + (ord(char) - ord("0"))
    return result | (octet << shift)


def five_tuple_hash(tuple_: FiveTuple) -> int:
    h = 0
    for value in (
        tuple_.src_ip,
        tuple_.dst_ip,
        tuple_.src_port,
        tuple_.dst_port,
        tuple_.protocol,
    ):
        h ^= hash(value) + 0x9E3779B9 + ((h << 6) & 0xFFFFFFFFFFFFFFFF) + (h >> 2)
        h &= 0xFFFFFFFFFFFFFFFF
    return h


def app_type_to_string(app_type: AppType) -> str:
    return _APP_TYPE_NAMES.get(app_type, "Unknown")


def app_type_from_string(name: str) -> AppType | None:
    return _NAME_TO_APP_TYPE.get(name)


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()

    if any(
        token in lower_sni
        for token in ("google", "gstatic", "googleapis", "ggpht", "gvt1")
    ):
        return AppType.GOOGLE

    if any(token in lower_sni for token in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE

    if any(
        token in lower_sni
        for token in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")
    ):
        return AppType.FACEBOOK

    if "instagram" in lower_sni or "cdninstagram" in lower_sni:
        return AppType.INSTAGRAM

    if "whatsapp" in lower_sni or "wa.me" in lower_sni:
        return AppType.WHATSAPP

    if any(token in lower_sni for token in ("netflix", "nflxvideo", "nflximg","nflxext.com ","nflxso.net","nflxso.com","nflxext")):
        return AppType.NETFLIX

    if any(
        token in lower_sni
        for token in ("amazon", "amazonaws", "cloudfront", "aws")
    ):
        return AppType.AMAZON

    if any(
        token in lower_sni
        for token in ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")
    ):
        return AppType.MICROSOFT

    if any(token in lower_sni for token in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    if "telegram" in lower_sni or "t.me" in lower_sni:
        return AppType.TELEGRAM

    if any(
        token in lower_sni
        for token in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")
    ):
        return AppType.TIKTOK

    if "spotify" in lower_sni or "scdn.co" in lower_sni:
        return AppType.SPOTIFY

    if "zoom" in lower_sni:
        return AppType.ZOOM

    if "discord" in lower_sni or "discordapp" in lower_sni:
        return AppType.DISCORD

    if "github" in lower_sni or "githubusercontent" in lower_sni:
        return AppType.GITHUB

    if "cloudflare" in lower_sni or "cf-" in lower_sni:
        return AppType.CLOUDFLARE
    
    if any(token in lower_sni for token in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER



    return AppType.HTTPS
