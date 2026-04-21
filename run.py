#!/usr/bin/env python3
import argparse
import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

IMAGE_TAG = "tlshunter:0.5.0"
RESULT_RE = re.compile(r"\[RESULT\]\s+type=(\S+)\s+function=(\S+)\s+rva=(\S+)\s+fingerprint=(.+?)(?:\s+note=(\S+))?$")

ROLE_MAP = {
    "HKDF": "TLS 1.3 Derive-Secret",
    "SSL_LOG_SECRET": "BoringSSL keylog output",
    "PRF": "TLS 1.2 master secret derivation",
    "KEY_EXPANSION": "TLS 1.2 key block derivation",
}

JSON_KEY_MAP = {
    "HKDF": "hkdf",
    "SSL_LOG_SECRET": "ssl_log_secret",
    "PRF": "prf",
    "KEY_EXPANSION": "key_expansion",
}


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)


def ensure_image(project_root: Path):
    inspect = run(["docker", "image", "inspect", IMAGE_TAG])
    if inspect.returncode == 0:
        return

    result = run(["docker", "build", "-t", IMAGE_TAG, "-f", str(project_root / "Dockerfile"), "."], cwd=project_root)
    if result.returncode != 0:
        raise RuntimeError(f"Docker build failed:\n{result.stdout}\n{result.stderr}")


def _normalize_result_line(line: str) -> str:
    stripped = line.strip()
    marker = "[RESULT]"
    idx = stripped.find(marker)
    if idx == -1:
        return stripped
    return stripped[idx:]


def parse_results(output: str):
    parsed = {}
    for line in output.splitlines():
        normalized = _normalize_result_line(line)
        match = RESULT_RE.search(normalized)
        if not match:
            continue
        result_type, function_name, rva, fingerprint, note = match.groups()
        parsed[result_type] = {
            "function": function_name,
            "rva": rva,
            "fingerprint": fingerprint.strip(),
            "fingerprint_len": len([b for b in fingerprint.strip().split(" ") if b]),
            "role": ROLE_MAP.get(result_type, result_type),
        }
        if note:
            parsed[result_type]["note"] = note.replace("_", " ")
    return parsed


def build_output_json(binary: Path, parsed_results: dict):
    hook_points = {}
    for result_type, key in JSON_KEY_MAP.items():
        if result_type in parsed_results:
            hook_points[key] = parsed_results[result_type]

    return {
        "meta": {
            "binary": binary.name,
            "analysis_tool": "TLShunter phase2",
            "analysis_date": datetime.now(timezone.utc).isoformat(),
        },
        "hook_points": hook_points,
    }


def _docker_output_text(result: subprocess.CompletedProcess) -> str:
    return (result.stdout or "") + (result.stderr or "")


def analyze_binary(binary: Path, output: Path):
    project_root = Path(__file__).resolve().parent
    ensure_image(project_root)

    with tempfile.TemporaryDirectory(prefix="tlshunter-input-") as input_dir_str:
        input_dir = Path(input_dir_str)
        temp_binary = input_dir / binary.name
        shutil.copy2(binary, temp_binary)

        output_dir = output.parent.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        docker_cmd = [
            "docker", "run", "--rm",
            "--name", f"tlshunter_{binary.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "-v", f"{input_dir}:/usr/local/src/binaries",
            "-v", f"{output_dir}:/host_output",
            IMAGE_TAG,
        ]
        result = run(docker_cmd)
        combined_output = _docker_output_text(result)
        (output_dir / "docker_run_output.log").write_text(combined_output, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            raise RuntimeError(f"Docker run failed with exit code {result.returncode}:\n{combined_output}")

    parsed = parse_results(combined_output)
    data = build_output_json(binary, parsed)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    return parsed, output


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def fingerprint_prefix(value: str, prefix_bytes: int = 20) -> str:
    return " ".join(value.split()[:prefix_bytes])


def compare_results(result_path: Path, ground_truth_path: Path):
    result_data = load_json(result_path)
    ground_truth_data = load_json(ground_truth_path)

    result_hooks = result_data.get("hook_points", {})
    ground_truth_hooks = ground_truth_data.get("hook_points", {})
    all_keys = sorted(set(result_hooks) | set(ground_truth_hooks))

    diffs = []
    for key in all_keys:
        expected = ground_truth_hooks.get(key)
        actual = result_hooks.get(key)
        if expected is None:
            diffs.append(f"FAIL {key}: result has unexpected hook")
            continue
        if actual is None:
            diffs.append(f"FAIL {key}: missing in result")
            continue

        expected_rva = expected.get("rva")
        actual_rva = actual.get("rva")
        if expected_rva != actual_rva:
            diffs.append(f"FAIL {key}: rva mismatch expected={expected_rva} actual={actual_rva}")

        expected_fp = fingerprint_prefix(expected.get("fingerprint", ""))
        actual_fp = fingerprint_prefix(actual.get("fingerprint", ""))
        if expected_fp != actual_fp:
            diffs.append(
                f"FAIL {key}: fingerprint prefix mismatch expected='{expected_fp}' actual='{actual_fp}'"
            )

    passed = not diffs
    summary = [f"{'PASS' if passed else 'FAIL'} compare {result_path.name} vs {ground_truth_path.name}"]
    summary.extend(diffs or ["All hook points match: rva exact and fingerprint first 20 bytes match."])
    return passed, "\n".join(summary)


def render_report(results_dir: Path):
    json_files = sorted(
        [path for path in results_dir.glob("*.json") if path.is_file()],
        key=lambda path: path.name,
    )
    hooks = ["hkdf", "ssl_log_secret", "prf", "key_expansion"]

    header = [
        "# TLShunter Fingerprint Stability Report",
        "",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
        "",
        "| File | HKDF | SSL_LOG_SECRET | PRF | KEY_EXPANSION |",
        "| --- | --- | --- | --- | --- |",
    ]
    rows = []

    for path in json_files:
        data = load_json(path)
        hook_points = data.get("hook_points", {})
        cells = [path.name]
        for hook in hooks:
            item = hook_points.get(hook)
            if not item:
                cells.append("—")
                continue
            rva = item.get("rva", "?")
            fp = fingerprint_prefix(item.get("fingerprint", ""), prefix_bytes=8)
            cells.append(f"`{rva}` / `{fp}`")
        rows.append("| " + " | ".join(cells) + " |")

    if not rows:
        rows.append("| (no json files) | — | — | — | — |")

    return "\n".join(header + rows) + "\n"


def analyze_batch(batch_dir: Path, output_dir: Path):
    candidates = sorted([path for path in batch_dir.iterdir() if path.is_file()])
    if not candidates:
        raise RuntimeError(f"No binaries found in {batch_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    summaries = []
    for binary in candidates:
        output_path = output_dir / f"{binary.name}.json"
        parsed, _ = analyze_binary(binary, output_path)
        summaries.append((binary, output_path, parsed))
    return summaries


def main():
    parser = argparse.ArgumentParser(description="Run TLShunter analyzer")
    parser.add_argument("--binary", help="Path to target binary")
    parser.add_argument("--output", help="Path to output JSON file")
    parser.add_argument("--batch", help="Analyze all binaries in a directory")
    parser.add_argument("--batch-output-dir", help="Output directory for batch results")
    parser.add_argument("--compare", help="Compare a result JSON against a ground truth JSON file")
    parser.add_argument("--report", help="Generate a Markdown fingerprint stability report for a results directory")
    parser.add_argument("--report-out", help="Path to write the generated Markdown report")
    args = parser.parse_args()

    if args.binary:
        if not args.output:
            raise SystemExit("--output is required with --binary")
        binary = Path(args.binary).resolve()
        output = Path(args.output).resolve()
        if not binary.is_file():
            raise SystemExit(f"Binary not found: {binary}")

        parsed, output_path = analyze_binary(binary, output)
        print(f"[*] Wrote analysis JSON to {output_path}")
        if parsed:
            for result_type, values in parsed.items():
                print(f"[OK] {result_type}: {values['rva']} {values['function']}")
        else:
            print("[!] No [RESULT] lines were parsed")

        if args.compare:
            passed, text = compare_results(output_path, Path(args.compare).resolve())
            print(text)
            raise SystemExit(0 if passed else 1)
        return

    if args.batch:
        if not args.batch_output_dir:
            raise SystemExit("--batch-output-dir is required with --batch")
        batch_dir = Path(args.batch).resolve()
        output_dir = Path(args.batch_output_dir).resolve()
        summaries = analyze_batch(batch_dir, output_dir)
        for binary, output_path, parsed in summaries:
            print(f"[*] {binary.name} -> {output_path}")
            print(f"    hooks: {', '.join(parsed.keys()) if parsed else '(none)'}")
        return

    if args.compare:
        if not args.output:
            raise SystemExit("--output must point to the result JSON when using --compare standalone")
        passed, text = compare_results(Path(args.output).resolve(), Path(args.compare).resolve())
        print(text)
        raise SystemExit(0 if passed else 1)

    if args.report:
        report = render_report(Path(args.report).resolve())
        if args.report_out:
            Path(args.report_out).resolve().write_text(report, encoding="utf-8")
            print(f"[*] Report written to {Path(args.report_out).resolve()}")
        else:
            print(report, end="")
        return

    parser.print_help()


if __name__ == "__main__":
    main()

