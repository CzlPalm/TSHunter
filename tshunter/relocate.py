#!/usr/bin/env python3
import argparse
import hashlib
import json
import sqlite3
import struct
from pathlib import Path

try:
    import pefile
except ImportError:
    pefile = None

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    ELFFile = None

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "fingerprints.db"


def parse_hex_bytes(fp: str) -> bytes:
    parts = [item for item in fp.strip().split() if item]
    return bytes(int(item, 16) for item in parts)


def first_n_bytes(fp: str, n: int) -> bytes:
    return parse_hex_bytes(" ".join(fp.split()[:n]))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hex_int(value: int) -> str:
    prefix = "-0x" if value < 0 else "0x"
    return f"{prefix}{abs(value):X}"


def count_matching_bytes(buf: bytes, offset: int, needle: bytes) -> int:
    matched = 0
    limit = min(len(needle), len(buf) - offset)
    for idx in range(limit):
        if buf[offset + idx] != needle[idx]:
            break
        matched += 1
    return matched


def scan_all(buf: bytes, needle: bytes) -> list[int]:
    hits = []
    start = 0
    while True:
        pos = buf.find(needle, start)
        if pos == -1:
            break
        hits.append(pos)
        start = pos + 1
    return hits


def compute_confidence(hit: dict) -> float:
    conf = hit["bytes_matched_extended"] / 40.0 if 40 else 0.0
    if hit["distance_from_source"] > 16 * 1024 * 1024:
        conf *= 0.7
    return round(conf, 3)


def determine_verdict(results: list[dict], all_deltas: list[int]) -> str:
    if results and all(item["match_type"] == "not_found" for item in results):
        return "FAIL"
    if any(item["match_type"] == "not_found" for item in results):
        return "PARTIAL"
    if not all_deltas:
        return "PARTIAL"
    ordered = sorted(all_deltas)
    median_delta = ordered[len(ordered) // 2]
    tolerance = max(int(abs(median_delta) * 0.1), 1024)
    if all(abs(delta - median_delta) <= tolerance for delta in all_deltas):
        return "OK"
    return "PARTIAL"


def select_best(scored_hits: list[dict]) -> dict:
    strong = [item for item in scored_hits if item["bytes_matched_extended"] >= 32]
    if strong:
        return min(strong, key=lambda item: item["distance_from_source"])
    medium = [item for item in scored_hits if item["bytes_matched_extended"] >= 20]
    if medium:
        return min(medium, key=lambda item: item["distance_from_source"])
    return min(scored_hits, key=lambda item: item["distance_from_source"])


def load_elf_text(path: Path) -> dict:
    if ELFFile is None:
        raise SystemExit("pyelftools is required for ELF binaries. Run: pip install -r requirements.txt")
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        text_section = elf.get_section_by_name(".text")
        if text_section is not None:
            return {
                "format": "elf",
                "image_base": 0,
                "text_start_rva": int(text_section["sh_addr"]),
                "text_size": int(text_section["sh_size"]),
                "text_bytes": text_section.data(),
            }
        segments = [seg for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD" and (seg["p_flags"] & 0x1)]
        if not segments:
            raise SystemExit("No executable section/segment found in ELF")
        seg = min(segments, key=lambda item: int(item["p_vaddr"]))
        return {
            "format": "elf",
            "image_base": 0,
            "text_start_rva": int(seg["p_vaddr"]),
            "text_size": int(seg["p_filesz"]),
            "text_bytes": seg.data(),
        }


def load_pe_text(path: Path) -> dict:
    if pefile is None:
        raise SystemExit("pefile is required for PE binaries. Run: pip install -r requirements.txt")
    pe = pefile.PE(str(path))
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00")
        if name == b".text":
            return {
                "format": "pe",
                "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
                "text_start_rva": int(section.VirtualAddress),
                "text_size": int(section.Misc_VirtualSize),
                "text_bytes": section.get_data(),
            }
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            return {
                "format": "pe",
                "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
                "text_start_rva": int(section.VirtualAddress),
                "text_size": int(section.Misc_VirtualSize),
                "text_bytes": section.get_data(),
            }
    raise SystemExit("No executable section found in PE")


def load_text_section(binary_path: Path) -> dict:
    with binary_path.open("rb") as handle:
        magic = handle.read(4)
    if magic.startswith(b"\x7fELF"):
        return load_elf_text(binary_path)
    if magic.startswith(b"MZ"):
        return load_pe_text(binary_path)
    if magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
        raise NotImplementedError("Mach-O is not implemented yet")
    raise SystemExit(f"Unsupported binary format: {binary_path}")


def connect_db(db_path: Path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def load_hooks_from_db(conn, browser: str, version: str, platform: str, arch: str):
    rows = conn.execute(
        """
        SELECT v.id AS version_id, v.image_base, hp.kind, hp.rva, hp.fingerprint, hp.fingerprint_len
        FROM versions v
        JOIN browsers b ON b.id = v.browser_id
        JOIN hook_points hp ON hp.version_id = v.id
        WHERE b.name=? AND v.version=? AND v.platform=? AND v.arch=?
        ORDER BY hp.kind
        """,
        (browser, version, platform, arch),
    ).fetchall()
    return [dict(row) for row in rows]


def build_summary(results: list[dict], all_deltas: list[int]) -> dict:
    median_delta = sorted(all_deltas)[len(all_deltas) // 2] if all_deltas else None
    return {
        "total_hooks": len(results),
        "relocated": sum(1 for item in results if item["match_type"] != "not_found"),
        "exact_match": sum(1 for item in results if item["match_type"] == "exact_match"),
        "shifted_match": sum(1 for item in results if item["match_type"] == "shifted_match"),
        "not_found": sum(1 for item in results if item["match_type"] == "not_found"),
        "delta_consistent": bool(all_deltas) and determine_verdict(results, all_deltas) == "OK",
        "median_delta": hex_int(median_delta) if median_delta is not None else None,
        "all_deltas": [hex_int(item) for item in all_deltas],
    }


def scan(binary_path: Path, hooks_from_db: list[dict], source_browser: str, source_version: str, source_platform: str, source_arch: str):
    loaded = load_text_section(binary_path)
    text_bytes = loaded["text_bytes"]
    text_start_rva = loaded["text_start_rva"]
    image_base = loaded["image_base"]

    results = []
    all_deltas = []

    for hook in hooks_from_db:
        prefix_20 = first_n_bytes(hook["fingerprint"], 20)
        extended_40 = first_n_bytes(hook["fingerprint"], 40)
        hits = scan_all(text_bytes, prefix_20)
        if not hits:
            results.append({
                "kind": hook["kind"],
                "source_rva": hook["rva"],
                "source_fingerprint_prefix": " ".join(hook["fingerprint"].split()[:20]),
                "new_rva": None,
                "delta": None,
                "confidence": 0.0,
                "match_type": "not_found",
                "scan_hits": [],
                "selected_hit_index": None,
                "selection_reason": "no_prefix20_hit",
            })
            continue

        scored_hits = []
        old_rva_int = int(hook["rva"], 16)
        for hit_offset in hits:
            extended_match = count_matching_bytes(text_bytes, hit_offset, extended_40)
            new_rva = hit_offset + text_start_rva - image_base
            distance = abs(new_rva - old_rva_int)
            scored_hits.append({
                "rva": new_rva,
                "bytes_matched_prefix": min(20, len(prefix_20)),
                "bytes_matched_extended": extended_match,
                "distance_from_source": distance,
            })

        selected = select_best(scored_hits)
        delta = selected["rva"] - old_rva_int
        all_deltas.append(delta)
        selected_idx = scored_hits.index(selected)
        if selected["bytes_matched_extended"] >= 32:
            reason = "nearest_to_source_rva_with_extended_verification"
        elif selected["bytes_matched_extended"] >= 20:
            reason = "nearest_to_source_rva_with_medium_extended_verification"
        else:
            reason = "nearest_to_source_rva_with_prefix_only_match"
        results.append({
            "kind": hook["kind"],
            "source_rva": hook["rva"],
            "source_fingerprint_prefix": " ".join(hook["fingerprint"].split()[:20]),
            "new_rva": hex_int(selected["rva"]),
            "delta": hex_int(delta),
            "confidence": compute_confidence(selected),
            "match_type": "exact_match" if delta == 0 else "shifted_match",
            "scan_hits": [{
                "rva": hex_int(item["rva"]),
                "bytes_matched_prefix": item["bytes_matched_prefix"],
                "bytes_matched_extended": item["bytes_matched_extended"],
                "distance_from_source": item["distance_from_source"],
            } for item in scored_hits],
            "selected_hit_index": selected_idx,
            "selection_reason": reason,
        })

    verdict = determine_verdict(results, all_deltas)
    return {
        "target": {
            "path": str(binary_path),
            "sha256": sha256_file(binary_path),
            "size": binary_path.stat().st_size,
            "image_base": hex_int(image_base),
            "text_start_rva": hex_int(text_start_rva),
            "text_size": loaded["text_size"],
        },
        "source_version": {
            "browser": source_browser,
            "version": source_version,
            "platform": source_platform,
            "arch": source_arch,
        },
        "relocation_summary": build_summary(results, all_deltas),
        "hooks": results,
        "verdict": verdict,
        "tool_version": "0.1.0",
    }


def probe(binary_path: Path, fingerprint: str, old_rva: str, old_image_base: str | None):
    hook = {
        "kind": "probe",
        "rva": old_rva,
        "fingerprint": fingerprint,
        "fingerprint_len": len(fingerprint.split()),
    }
    result = scan(binary_path, [hook], "probe", "probe", "unknown", "unknown")
    if old_image_base:
        result["source_old_image_base"] = old_image_base
    return result


def main():
    parser = argparse.ArgumentParser(description="Fingerprint-based RVA relocation")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_parser = sub.add_parser("scan", help="Relocate all hooks from a source version")
    scan_parser.add_argument("--binary", required=True)
    scan_parser.add_argument("--db", default=str(DEFAULT_DB))
    scan_parser.add_argument("--source-browser", required=True)
    scan_parser.add_argument("--source-version", required=True)
    scan_parser.add_argument("--source-platform", required=True)
    scan_parser.add_argument("--source-arch", required=True)
    scan_parser.add_argument("--output", required=True)

    probe_parser = sub.add_parser("probe", help="Probe one fingerprint without DB")
    probe_parser.add_argument("--binary", required=True)
    probe_parser.add_argument("--fingerprint", required=True)
    probe_parser.add_argument("--old-rva", required=True)
    probe_parser.add_argument("--old-image-base")
    probe_parser.add_argument("--output")

    args = parser.parse_args()

    if args.cmd == "scan":
        conn = connect_db(Path(args.db))
        hooks = load_hooks_from_db(conn, args.source_browser, args.source_version, args.source_platform, args.source_arch)
        if not hooks:
            raise SystemExit("No source hooks found in DB")
        payload = scan(Path(args.binary), hooks, args.source_browser, args.source_version, args.source_platform, args.source_arch)
        output = Path(args.output)
        output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[*] Relocate verdict: {payload['verdict']}")
        print(f"[*] Output written to {output}")
        return

    payload = probe(Path(args.binary), args.fingerprint, args.old_rva, args.old_image_base)
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"[*] Output written to {args.output}")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()

