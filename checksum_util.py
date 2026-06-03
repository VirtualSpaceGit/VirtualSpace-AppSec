import zlib
import hashlib
import struct
import json
from typing import Any

MAGIC = b'DS02'
VERSION = 2

def compute_adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF

def compute_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def compute_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def build_header(data_len: int, checksum: int) -> bytes:
    return MAGIC + struct.pack('>BII', VERSION, data_len, checksum)

def parse_header(header: bytes) -> dict:
    if len(header) < 13:
        raise ValueError("Header too short")
    magic = header[:4]
    if magic != MAGIC:
        raise ValueError("Invalid magic bytes")
    version, data_len, checksum = struct.unpack('>BII', header[4:13])
    return {"version": version, "data_len": data_len, "checksum": checksum}

def verify_integrity(data: bytes, expected_checksum: int) -> bool:
    return compute_crc32(data) == expected_checksum

def package_payload(obj: Any) -> bytes:
    raw = json.dumps(obj).encode('utf-8')
    compressed = zlib.compress(raw)
    checksum = compute_crc32(compressed)
    header = build_header(len(compressed), checksum)
    return header + compressed

def unpack_payload(data: bytes) -> Any:
    header = parse_header(data[:13])
    payload = data[13:]
    if not verify_integrity(payload, header["checksum"]):
        raise ValueError("Checksum mismatch")
    raw = zlib.decompress(payload)
    return json.loads(raw.decode('utf-8'))

if __name__ == "__main__":
    sample = {"key": "value", "numbers": [1, 2, 3], "nested": {"flag": True}}
    packed = package_payload(sample)
    print("SHA256:", compute_sha256(packed))
    print("CRC32:", hex(compute_crc32(packed)))
    print("Adler32:", hex(compute_adler32(packed)))
    result = unpack_payload(packed)
    print("Unpacked:", result)