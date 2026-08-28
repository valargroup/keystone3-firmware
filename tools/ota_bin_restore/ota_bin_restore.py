#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Restore the uncompressed firmware image from a compressed+signed
keystone3.bin OTA package.

Usage:
    python3 ota_bin_restore.py <keystone3.bin> [uncompressed.bin]

If no output path is given, writes uncompressed.bin next to the input.

Setup (see requirements.txt):
    pip install Cython
    pip install --no-build-isolation -r requirements.txt
"""

import os
import struct
import sys

# Pin the decompressor. pyquicklz's version determines the bundled QuickLZ C
# source and its compile-time compression level, i.e. the decompression output
# itself -- so we refuse to run against any other version.
REQUIRED_QUICKLZ_VERSION = "1.4.1"

try:
    import quicklz  # pyquicklz: decompress(bytes) -> bytes, one chunk per call
except ImportError:
    sys.exit(
        "error: the pinned 'pyquicklz' library is required.\n"
        "       pip install Cython\n"
        "       pip install --no-build-isolation -r requirements.txt"
    )

_found = getattr(quicklz, "__version__", None)
if _found != REQUIRED_QUICKLZ_VERSION:
    sys.exit(
        "error: pyquicklz %s is required for reproducible output, found %s.\n"
        "       reinstall the pinned version:\n"
        "       pip install --no-build-isolation --force-reinstall -r requirements.txt"
        % (REQUIRED_QUICKLZ_VERSION, _found)
    )


def qlz_size_compressed(source):
    """Compressed length of the QuickLZ chunk starting at `source` (from its header)."""
    n = 4 if (source[0] & 2) == 2 else 1
    r = int.from_bytes(source[1:1 + n], "little")
    return r & (0xFFFFFFFF >> ((4 - n) * 8))


def restore(content):
    # The OTA header is length-prefixed: a 4-byte little-endian size, the header
    # itself, then 1 padding byte. Skip past all of it to reach the QuickLZ chunk
    # stream, then decompress every chunk to the end of the data.
    head_size = struct.unpack_from("<i", content, 0)[0]
    data = content[head_size + 4 + 1:]
    out = bytearray()
    offset = 0
    while offset < len(data):
        csize = qlz_size_compressed(data[offset:])
        out += quicklz.decompress(bytes(data[offset:offset + csize]))
        offset += csize
    return bytes(out)


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 ota_bin_restore.py <keystone3.bin> [uncompressed.bin]")
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(src), "uncompressed.bin")
    open(dst, "wb").write(restore(open(src, "rb").read()))


if __name__ == "__main__":
    main()
