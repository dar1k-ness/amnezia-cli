from __future__ import annotations

import base64
import struct
import zlib
from dataclasses import dataclass


TOKEN_PREFIX = "vpn://"
AMNEZIA_SIGNATURE = b"\x00\x00\x00\xff"


@dataclass(frozen=True)
class DecodedToken:
    payload: bytes
    used_signature: bool


def _pad_base64url(data: str) -> str:
    remainder = len(data) % 4
    if remainder == 0:
        return data
    return data + "=" * (4 - remainder)


def qt_compress(payload: bytes) -> bytes:
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("Payload too large for Qt qCompress format")
    compressed = zlib.compress(payload, level=6)
    return struct.pack(">I", len(payload)) + compressed


def qt_uncompress(blob: bytes) -> bytes:
    if len(blob) < 5:
        raise ValueError("Invalid qCompress payload")
    expected_size = struct.unpack(">I", blob[:4])[0]
    payload = zlib.decompress(blob[4:])
    if expected_size not in (0xFF, len(payload)):
        raise ValueError("qCompress size prefix does not match payload size")
    return payload


def encode_token(payload: bytes, *, with_signature: bool = False) -> str:
    if with_signature:
        blob = AMNEZIA_SIGNATURE + zlib.compress(payload, level=6)
    else:
        blob = qt_compress(payload)
    encoded = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
    return f"{TOKEN_PREFIX}{encoded}"


def decode_token(token: str) -> DecodedToken:
    normalized = token.strip()
    if normalized.startswith(TOKEN_PREFIX):
        normalized = normalized[len(TOKEN_PREFIX) :]
    blob = base64.urlsafe_b64decode(_pad_base64url(normalized))

    if blob.startswith(AMNEZIA_SIGNATURE):
        return DecodedToken(payload=qt_uncompress(blob), used_signature=True)
    return DecodedToken(payload=qt_uncompress(blob), used_signature=False)

