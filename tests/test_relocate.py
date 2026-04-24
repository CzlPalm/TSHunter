from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tshunter import relocate as fr


def make_fp(prefix: bytes, length: int = 40) -> str:
    data = prefix + bytes(range(len(prefix), length))
    return " ".join(f"{b:02X}" for b in data)


def make_loaded(text: bytes, text_start_rva: int = 0x1000):
    return {
        "format": "elf",
        "image_base": 0,
        "text_start_rva": text_start_rva,
        "text_size": len(text),
        "text_bytes": text,
    }


def test_exact_match_when_fingerprint_at_same_offset(monkeypatch, tmp_path):
    prefix = bytes(range(40))
    text = b"\x90" * 0x80 + prefix + b"\x90" * 0x80
    monkeypatch.setattr(fr, "load_text_section", lambda _: make_loaded(text, 0x1000))
    monkeypatch.setattr(fr, "sha256_file", lambda _: "dummy")
    binary = tmp_path / "mock.bin"
    binary.write_bytes(b"test")

    hooks = [{"kind": "hkdf", "rva": "0x1080", "fingerprint": make_fp(prefix), "fingerprint_len": 40}]
    result = fr.scan(binary, hooks, "chrome", "143.0.1", "linux", "x86_64")

    hook = result["hooks"][0]
    assert hook["match_type"] == "exact_match"
    assert hook["delta"] == "0x0"
    assert result["verdict"] == "OK"


def test_shifted_match_small_drift(monkeypatch, tmp_path):
    prefix = bytes(range(40))
    text = b"\x90" * 0x100 + prefix + b"\x90" * 0x80
    monkeypatch.setattr(fr, "load_text_section", lambda _: make_loaded(text, 0x1000))
    monkeypatch.setattr(fr, "sha256_file", lambda _: "dummy")
    binary = tmp_path / "shift.bin"
    binary.write_bytes(b"test")

    hooks = [{"kind": "hkdf", "rva": "0x1000", "fingerprint": make_fp(prefix), "fingerprint_len": 40}]
    result = fr.scan(binary, hooks, "chrome", "143.0.1", "linux", "x86_64")

    hook = result["hooks"][0]
    assert hook["match_type"] == "shifted_match"
    assert hook["delta"] == "0x100"
    assert result["relocation_summary"]["delta_consistent"] is True


def test_not_found_when_fingerprint_absent(monkeypatch, tmp_path):
    text = b"\x90" * 512
    monkeypatch.setattr(fr, "load_text_section", lambda _: make_loaded(text, 0x1000))
    monkeypatch.setattr(fr, "sha256_file", lambda _: "dummy")
    binary = tmp_path / "absent.bin"
    binary.write_bytes(b"test")

    hooks = [{"kind": "hkdf", "rva": "0x1000", "fingerprint": make_fp(bytes(range(40))), "fingerprint_len": 40}]
    result = fr.scan(binary, hooks, "chrome", "143.0.1", "linux", "x86_64")

    hook = result["hooks"][0]
    assert hook["match_type"] == "not_found"
    assert result["verdict"] == "FAIL"


def test_multi_hit_disambiguation_by_distance(monkeypatch, tmp_path):
    prefix = bytes(range(40))
    text = bytearray(b"\x90" * 0x5000)
    text[0x200:0x200 + 40] = prefix
    text[0x3000:0x3000 + 40] = prefix
    monkeypatch.setattr(fr, "load_text_section", lambda _: make_loaded(bytes(text), 0x1000))
    monkeypatch.setattr(fr, "sha256_file", lambda _: "dummy")
    binary = tmp_path / "distance.bin"
    binary.write_bytes(b"test")

    hooks = [{"kind": "hkdf", "rva": "0x1200", "fingerprint": make_fp(prefix), "fingerprint_len": 40}]
    result = fr.scan(binary, hooks, "chrome", "143.0.1", "linux", "x86_64")

    hook = result["hooks"][0]
    assert hook["new_rva"] == "0x1200"
    assert hook["selected_hit_index"] == 0


def test_multi_hit_disambiguation_by_extended(monkeypatch, tmp_path):
    prefix20 = bytes(range(20))
    good = prefix20 + bytes(range(20, 40))
    weak = prefix20 + b"\xFF" * 20
    text = bytearray(b"\x90" * 0x3000)
    text[0x200:0x200 + 40] = weak
    text[0x400:0x400 + 40] = good
    monkeypatch.setattr(fr, "load_text_section", lambda _: make_loaded(bytes(text), 0x1000))
    monkeypatch.setattr(fr, "sha256_file", lambda _: "dummy")
    binary = tmp_path / "extended.bin"
    binary.write_bytes(b"test")

    hooks = [{"kind": "hkdf", "rva": "0x1800", "fingerprint": make_fp(good), "fingerprint_len": 40}]
    result = fr.scan(binary, hooks, "chrome", "143.0.1", "linux", "x86_64")

    hook = result["hooks"][0]
    assert hook["new_rva"] == "0x1400"
    assert hook["scan_hits"][1]["bytes_matched_extended"] == 40


def test_verdict_ok_when_deltas_consistent(monkeypatch, tmp_path):
    prefixes = [bytes([n]) * 40 for n in range(1, 5)]
    text = bytearray(b"\x90" * 0x1000)
    hooks = []
    for idx, prefix in enumerate(prefixes):
        source_rva = 0x1000 + idx * 0x80
        target_off = 0x100 + idx * 0x80
        text[target_off:target_off + 40] = prefix
        hooks.append({
            "kind": ["hkdf", "prf", "key_expansion", "ssl_log_secret"][idx],
            "rva": hex(source_rva),
            "fingerprint": make_fp(prefix),
            "fingerprint_len": 40,
        })
    monkeypatch.setattr(fr, "load_text_section", lambda _: make_loaded(bytes(text), 0x1100))
    monkeypatch.setattr(fr, "sha256_file", lambda _: "dummy")
    binary = tmp_path / "ok.bin"
    binary.write_bytes(b"test")

    result = fr.scan(binary, hooks, "chrome", "143.0.1", "linux", "x86_64")
    assert result["verdict"] == "OK"
    assert result["relocation_summary"]["delta_consistent"] is True


def test_verdict_partial_when_deltas_inconsistent(monkeypatch, tmp_path):
    prefixes = [bytes([n]) * 40 for n in range(1, 5)]
    text = bytearray(b"\x90" * 0x3000)
    hooks = []
    offsets = [0x100, 0x300, 0x900, 0x1400]
    for idx, prefix in enumerate(prefixes):
        text[offsets[idx]:offsets[idx] + 40] = prefix
        hooks.append({
            "kind": ["hkdf", "prf", "key_expansion", "ssl_log_secret"][idx],
            "rva": hex(0x1000 + idx * 0x80),
            "fingerprint": make_fp(prefix),
            "fingerprint_len": 40,
        })
    monkeypatch.setattr(fr, "load_text_section", lambda _: make_loaded(bytes(text), 0x1000))
    monkeypatch.setattr(fr, "sha256_file", lambda _: "dummy")
    binary = tmp_path / "partial.bin"
    binary.write_bytes(b"test")

    result = fr.scan(binary, hooks, "chrome", "143.0.1", "linux", "x86_64")
    assert result["verdict"] == "PARTIAL"
    assert result["relocation_summary"]["delta_consistent"] is False


def test_scan_reads_from_db(monkeypatch, tmp_path):
    db = tmp_path / "test.db"
    binary = tmp_path / "db.bin"
    binary.write_bytes(b"test")
    monkeypatch.setattr(fr, "load_text_section", lambda _: make_loaded(b"\x90" * 0x80 + bytes(range(40)), 0x1000))
    monkeypatch.setattr(fr, "sha256_file", lambda _: "dummy")

    import sqlite3
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE browsers(id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE versions(id INTEGER PRIMARY KEY, browser_id INTEGER, version TEXT, platform TEXT, arch TEXT, image_base TEXT);
        CREATE TABLE hook_points(id INTEGER PRIMARY KEY, version_id INTEGER, kind TEXT, rva TEXT, fingerprint TEXT, fingerprint_len INTEGER);
        INSERT INTO browsers(id, name) VALUES (1, 'chrome');
        INSERT INTO versions(id, browser_id, version, platform, arch, image_base) VALUES (1, 1, '143.0.1', 'linux', 'x86_64', '0x0');
        INSERT INTO hook_points(version_id, kind, rva, fingerprint, fingerprint_len)
        VALUES (1, 'hkdf', '0x1080', '', 40);
        """
    )
    conn.execute(
        "UPDATE hook_points SET fingerprint=?, fingerprint_len=? WHERE version_id=1 AND kind='hkdf'",
        (make_fp(bytes(range(40))), 40),
    )
    conn.commit()

    rows = fr.load_hooks_from_db(fr.connect_db(db), "chrome", "143.0.1", "linux", "x86_64")
    result = fr.scan(binary, rows, "chrome", "143.0.1", "linux", "x86_64")
    assert len(rows) == 1
    assert result["hooks"][0]["match_type"] == "exact_match"
