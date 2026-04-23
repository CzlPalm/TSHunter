#!/usr/bin/env python3
from __future__ import annotations

import struct
from pathlib import Path

ELF_HEADER_SIZE = 64
PROGRAM_HEADER_SIZE = 56
SECTION_HEADER_SIZE = 64


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def make_minimal_elf(text_content: bytes, text_virt_addr: int = 0x401000, text_file_offset: int = 0x1000) -> bytes:
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = text_file_offset
    shstrtab_offset = align(text_offset + len(text_content), 0x10)
    shoff = align(shstrtab_offset + len(shstrtab), 0x10)

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8),
        2,
        0x3E,
        1,
        text_virt_addr,
        ELF_HEADER_SIZE,
        shoff,
        0,
        ELF_HEADER_SIZE,
        PROGRAM_HEADER_SIZE,
        1,
        SECTION_HEADER_SIZE,
        3,
        2,
    )

    phdr = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        text_virt_addr - text_file_offset,
        text_virt_addr - text_file_offset,
        shoff + SECTION_HEADER_SIZE * 3,
        shoff + SECTION_HEADER_SIZE * 3,
        0x1000,
    )

    null_sh = bytes(SECTION_HEADER_SIZE)
    text_sh = struct.pack(
        "<IIQQQQIIQQ",
        1,
        1,
        0x6,
        text_virt_addr,
        text_offset,
        len(text_content),
        0,
        0,
        16,
        0,
    )
    shstrtab_sh = struct.pack(
        "<IIQQQQIIQQ",
        7,
        3,
        0,
        0,
        shstrtab_offset,
        len(shstrtab),
        0,
        0,
        1,
        0,
    )

    blob = bytearray()
    blob += ehdr
    blob += phdr
    blob += bytes(text_offset - len(blob))
    blob += text_content
    blob += bytes(shstrtab_offset - len(blob))
    blob += shstrtab
    blob += bytes(shoff - len(blob))
    blob += null_sh
    blob += text_sh
    blob += shstrtab_sh
    return bytes(blob)


def write_mock_elf(path: str | Path, text_content: bytes, text_virt_addr: int = 0x401000) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(make_minimal_elf(text_content, text_virt_addr=text_virt_addr))
    return out


if __name__ == "__main__":
    sample = b"\x90" * 64 + b"\xC3"
    target = Path(__file__).resolve().parent / "mock_sample.elf"
    write_mock_elf(target, sample)
    print(target)

