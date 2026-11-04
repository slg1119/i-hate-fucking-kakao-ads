#!/usr/bin/env python3
"""Prepare an unsigned, version-pinned analysis candidate; never edit the installed app."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct

SOURCE_APP = Path("/Applications/KakaoTalk.app")
SOURCE_BINARY = SOURCE_APP / "Contents/MacOS/KakaoTalk"
EXPECTED_UNIVERSAL = "456e1a3ed7a87168888bdb8c6e4894764a028e62c0af68562a760d9909d2bb65"
EXPECTED_ARM64 = "16cbbfe19557b33ceeef6f490c3eb0abf4b047425a261a3c84ae496bd180d83b"
SLICE_OFFSET = 0xB0A4B0
EXPECTED_BYTES = bytes.fromhex("f4 4f be a9 fd 7b 01 a9")
REPLACEMENT = bytes.fromhex("00 00 80 52 c0 03 5f d6")  # mov w0, #0; ret


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prepare(data):
    if digest(data) != EXPECTED_UNIVERSAL:
        raise ValueError("Installed binary differs from the analyzed 26.9.0 (2006) build; refusing to patch.")
    magic, count = struct.unpack_from(">II", data)
    if magic != 0xCAFEBABE:
        raise ValueError("Expected the analyzed universal Mach-O.")
    arm = []
    for index in range(count):
        cpu, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + index * 20)
        if cpu == 0x0100000C:
            arm.append((offset, size))
    if len(arm) != 1:
        raise ValueError("Expected exactly one arm64 slice.")
    start, size = arm[0]
    if digest(data[start:start+size]) != EXPECTED_ARM64:
        raise ValueError("arm64 slice identity mismatch.")
    site = start + SLICE_OFFSET
    if data[site:site+8] != EXPECTED_BYTES:
        raise ValueError("Instruction bytes at the patch site differ.")
    result = bytearray(data)
    result[site:site+8] = REPLACEMENT
    assert result[:site] == data[:site] and result[site+8:] == data[site+8:]
    return bytes(result), {
        "source_sha256": digest(data), "candidate_sha256": digest(result),
        "architecture": "arm64", "analysis_address": "0x100b0a4b0",
        "arm64_slice_file_offset": hex(SLICE_OFFSET), "universal_file_offset": hex(site),
        "before": EXPECTED_BYTES.hex(" "), "after": REPLACEMENT.hex(" "),
        "candidate_status": "static candidate; signature and live UI unverified",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    destinations = parser.add_mutually_exclusive_group()
    destinations.add_argument("--output-binary", type=Path,
                              help="Write a separate universal binary; no signing or launch")
    destinations.add_argument("--app-copy", type=Path,
                              help="Copy the installed app to a new .app directory, then patch only that copy")
    args = parser.parse_args()
    try:
        candidate, report = prepare(SOURCE_BINARY.read_bytes())
        destination = args.output_binary or args.app_copy
        if destination:
            destination = destination.expanduser().resolve()
            if destination == SOURCE_APP or SOURCE_APP in destination.parents:
                raise ValueError("Destination must be outside the installed application.")
            if destination.exists():
                raise ValueError("Destination already exists; refusing to overwrite.")
            if args.app_copy:
                if destination.suffix != ".app":
                    raise ValueError("Application copy destination must end in .app.")
                shutil.copytree(SOURCE_APP, destination, symlinks=True)
                binary = destination / "Contents/MacOS/KakaoTalk"
                binary.write_bytes(candidate)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as stream:
                    stream.write(candidate)
                shutil.copymode(SOURCE_BINARY, destination)
                binary = destination
            report["output"] = str(binary)
            if digest(binary.read_bytes()) != report["candidate_sha256"]:
                raise ValueError("Written candidate digest mismatch.")
        else:
            report["mode"] = "check only; no output written"
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
