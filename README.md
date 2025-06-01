![Exploit Demo](https://media.discordapp.net/attachments/1368719799311667213/1378822738076242113/image.png?ex=683e003e&is=683caebe&hm=4e311c15277d10bb1a13d42cf4cb8ddf5078a949a44cd119e2219a280e26967e&=&format=webp&quality=lossless&width=1850&height=678)


FFmpeg-Ghost-HLS

An advanced FFmpeg exploit generator that abuses HLS playlist parsing and AES-XBIN chaining inside malformed AVI containers to create weaponized media payloads

--

Overview

FFmpeg-Ghost-HLS is a proof-of-concept generator designed to exploit how FFmpeg handles AVI container files with embedded HLS playlists and AES-128 encrypted segments. This tool dynamically embeds HLS-style media directives and XOR-encrypted AES blocks inside an AVI payload to force arbitrary file reads, memory leaks, or potential codec-based attack vectors when processed by FFmpeg or any player or library that leverages it

--

What it does

Crafts a malformed but valid AVI container with embedded HLS playlist data

Embeds AES-128 ECB blocks disguised via XBIN and decryptable via XOR echoing

Uses a static AES key named GAMMA and ECB mode to manipulate IVs

Inserts structured EXT-X-BYTERANGE playlist directives to read arbitrary offsets from attacker-defined file paths like file slash slash slash etc slash passwd

Injects randomness and packet repetition to bypass basic caching and detection

--

Installation

Make sure you are using Python 3.6 or higher and have permission to install system-wide packages

git clone https double slash github dot com slash SleepTheGod slash FFmpeg-Ghost-HLS dot git
cd FFmpeg-Ghost-HLS

pip install -r requirements.txt --break-system-packages

--

Usage

python3 main.py file slash slash slash etc slash passwd output.avi

Where
file slash slash slash etc slash passwd is the full path of the file you want to read
output.avi is the output filename for the generated malicious AVI container

To test with FFmpeg

ffmpeg -i output.avi -f null -

This may

Dump parts of the target file

Crash or leak memory

Trigger codec errors or memory access violations

--

requirements.txt contents

pycryptodome equal equal 3.20.0

--

Technical notes

main.py generates EXTINF EXT-X-KEY and EXT-X-BYTERANGE directives inside AVI chunks

AES ECB blocks are XOR’d using a custom GAMMA pattern to influence IV output

The AVI stream is padded with fake video and text packets named 00dc and 00tx to maintain decoder compatibility and confuse forensic tools

XBIN_HEADER simulates a terminal or graphic format header useful for blending into media pipelines

--

Use cases

Offensive media fuzzing

Red team payload delivery

Testing media parsers like FFmpeg VLC ffprobe against hybrid containers

Academic demonstrations of container or polyglot abuse

--

Legal warning

This code is provided for educational and authorized testing purposes only
Do not use against machines or data you do not own or have explicit permission to test
Use of this code for unauthorized exploitation or surveillance is illegal and unethical

--

Author

Taylor Christian Newsome
GitHub at github dot com slash SleepTheGod
