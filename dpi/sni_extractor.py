"""TLS SNI, HTTP Host, DNS, and QUIC extractors."""

from __future__ import annotations


def read_uint16_be(data: bytes, offset: int = 0) -> int:
    return (data[offset] << 8) | data[offset + 1]


def read_uint24_be(data: bytes, offset: int = 0) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


class SNIExtractor:
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @classmethod
    def is_tls_client_hello(cls, payload: bytes) -> bool:
        if len(payload) < 9:
            return False
        if payload[0] != cls.CONTENT_TYPE_HANDSHAKE:
            return False

        version = read_uint16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False

        record_length = read_uint16_be(payload, 3)
        if record_length > len(payload) - 5:
            return False

        if payload[5] != cls.HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @classmethod
    def extract(cls, payload: bytes) -> str | None:
        if not cls.is_tls_client_hello(payload):
            return None

        offset = 5
        offset += 4

        offset += 2
        offset += 32

        if offset >= len(payload):
            return None

        session_id_length = payload[offset]
        offset += 1 + session_id_length

        if offset + 2 > len(payload):
            return None
        cipher_suites_length = read_uint16_be(payload, offset)
        offset += 2 + cipher_suites_length

        if offset >= len(payload):
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length

        if offset + 2 > len(payload):
            return None
        extensions_length = read_uint16_be(payload, offset)
        offset += 2

        extensions_end = min(offset + extensions_length, len(payload))

        while offset + 4 <= extensions_end:
            extension_type = read_uint16_be(payload, offset)
            extension_length = read_uint16_be(payload, offset + 2)
            offset += 4

            if offset + extension_length > extensions_end:
                break

            if extension_type == cls.EXTENSION_SNI and extension_length >= 5:
                if offset + 5 > len(payload):
                    break
                sni_list_length = read_uint16_be(payload, offset)
                if sni_list_length < 3:
                    break
                sni_type = payload[offset + 2]
                sni_length = read_uint16_be(payload, offset + 3)
                if sni_type != cls.SNI_TYPE_HOSTNAME:
                    break
                if sni_length > extension_length - 5:
                    break
                return payload[offset + 5 : offset + 5 + sni_length].decode(
                    "ascii", errors="ignore"
                )

            offset += extension_length

        return None


class HTTPHostExtractor:
    _METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")

    @classmethod
    def is_http_request(cls, payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        return any(payload.startswith(method) for method in cls._METHODS)

    @classmethod
    def extract(cls, payload: bytes) -> str | None:
        if not cls.is_http_request(payload):
            return None

        for index in range(len(payload) - 5):
            if payload[index : index + 4].lower() == b"host" and payload[index + 4] == ord(":"):
                start = index + 5
                while start < len(payload) and payload[start] in (ord(" "), ord("\t")):
                    start += 1

                end = start
                while end < len(payload) and payload[end] not in (ord("\r"), ord("\n")):
                    end += 1

                if end > start:
                    host = payload[start:end].decode("ascii", errors="ignore")
                    colon_pos = host.find(":")
                    if colon_pos != -1:
                        host = host[:colon_pos]
                    return host
        return None


class DNSExtractor:
    @classmethod
    def is_dns_query(cls, payload: bytes) -> bool:
        if len(payload) < 12:
            return False
        if payload[2] & 0x80:
            return False
        qdcount = read_uint16_be(payload, 4)
        return qdcount > 0

    @classmethod
    def extract_query(cls, payload: bytes) -> str | None:
        if not cls.is_dns_query(payload):
            return None

        offset = 12
        labels: list[str] = []

        while offset < len(payload):
            label_length = payload[offset]
            if label_length == 0:
                break
            if label_length > 63:
                break
            offset += 1
            if offset + label_length > len(payload):
                break
            labels.append(payload[offset : offset + label_length].decode("ascii", errors="ignore"))
            offset += label_length

        return ".".join(labels) if labels else None


class QUICSNIExtractor:
    @classmethod
    def is_quic_initial(cls, payload: bytes) -> bool:
        if len(payload) < 5:
            return False
        return (payload[0] & 0x80) != 0

    @classmethod
    def extract(cls, payload: bytes) -> str | None:
        if not cls.is_quic_initial(payload):
            return None

        for index in range(len(payload) - 50):
            if payload[index] == 0x01:
                start = max(0, index - 5)
                result = SNIExtractor.extract(payload[start:])
                if result:
                    return result
        return None
