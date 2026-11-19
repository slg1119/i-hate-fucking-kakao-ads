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
PROFILES = {
    "456e1a3ed7a87168888bdb8c6e4894764a028e62c0af68562a760d9909d2bb65": {
        "version": "26.9.0 (2006)",
        "arm_hash": "16cbbfe19557b33ceeef6f490c3eb0abf4b047425a261a3c84ae496bd180d83b",
        "candidate_hash": "c2b646df3798f94ddff7e99d32b22fd41e07afc0237227f4b2299454ba867c6c",
        "sites": [{
            "offset": 0xB0A4B0,
            "original": bytes.fromhex("f4 4f be a9 fd 7b 01 a9"),
            "replacement": bytes.fromhex("00 00 80 52 c0 03 5f d6"),
            "analysis_address": "0x100b0a4b0",
        }],
    },
    "0c2b8d4d1240cffedde7232f04c7fc3875b3f667d16a69e3ed99b2bed9e83f4f": {
        "version": "26.10.0 (2010)",
        "arm_hash": "d2b310d0122e4db3bb574b2844045b84ca782b0bcf94f8131503ee34892a5463",
        "candidate_hash": "3ce9ce0e865fe96b5210a83c1825743b89583f66388a66ce4a480e7a4b443b4e",
        "sites": [
            {"offset": 0x11E0958, "original": bytes.fromhex("ef 29 fa 97"),
             "replacement": bytes.fromhex("00 00 80 52"), "analysis_address": "0x1011e0958"},
            {"offset": 0x11E09B4, "original": bytes.fromhex("d8 29 fa 97"),
             "replacement": bytes.fromhex("00 00 80 52"), "analysis_address": "0x1011e09b4"},
            {"offset": 0x1479940, "original": bytes.fromhex("80 04 00 36"),
             "replacement": bytes.fromhex("24 00 00 14"), "analysis_address": "0x101479940"},
        ],
    },
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def prepare(data):
    profile = PROFILES.get(digest(data))
    if not profile:
        raise ValueError("Installed binary differs from the analyzed builds; refusing to patch.")
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
    if digest(data[start:start+size]) != profile["arm_hash"]:
        raise ValueError("arm64 slice identity mismatch.")
    result = bytearray(data)
    site_reports = []
    for site in profile["sites"]:
        offset = site["offset"]
        before, after = site["original"], site["replacement"]
        if not before or len(before) != len(after) or offset < 0 or offset + len(before) > size:
            raise ValueError("Invalid patch site bounds or replacement length.")
        location = start + offset
        if data[location:location+len(before)] != before:
            raise ValueError("Instruction bytes at a patch site differ.")
        result[location:location+len(before)] = after
        site_reports.append({
            "analysis_address": site["analysis_address"],
            "arm64_slice_file_offset": hex(offset), "universal_file_offset": hex(location),
            "before": before.hex(" "), "after": after.hex(" "),
        })
    if digest(result) != profile["candidate_hash"]:
        raise ValueError("Patched candidate digest mismatch.")
    return bytes(result), {
        "version": profile["version"], "source_sha256": digest(data), "candidate_sha256": digest(result),
        "architecture": "arm64", "sites": site_reports,
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
