#!/usr/bin/env python3
"""
Usage:
    python run_test.py [--no-judgement] <oracle> <corpus|file>
    python run_test.py --table [--hash] [--no-judgement] <oracle> [<oracle> ...] <corpus|file>

Run an oracle against each file in corpus/{accept,iffy,malicious,reject}/ or a
single archive file and print a per-category summary with a list of failures.

Expected exit codes (security-minded: ambiguous input should be rejected):
    accept/    -> 0
    iffy/      -> 1
    malicious/ -> 1
    reject/    -> 1

With --no-judgement, iffy/ and malicious/ results are shown but not counted
as failures (no expected exit code is enforced for those categories).

Table mode:
    --table runs multiple oracles in parallel and prints a matrix showing only
    the test files where oracles disagree with each other or with the expected
    outcome.
    --hash shows per-oracle content hashes instead of accept/reject/vuln labels.
"""

import json
import hashlib
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


USAGE = __doc__.strip()


def oracle_display_name(oracle_path: str) -> str:
    """Return a short display name for an oracle.

    Uses basename (stripping .py/.js). If the result is generic ("oracle"),
    falls back to the parent directory name (e.g. "python", "go", "zig").
    """
    p = Path(oracle_path)
    name = p.stem if p.suffix in (".py", ".js") else p.name
    if name in ("oracle",) and p.parent.name:
        name = p.parent.name
    return name


def is_helper_oracle(oracle_path: str) -> bool:
    return Path(oracle_path).name == "dir-to-jsonl"


def run_oracle_on_file(oracle: str, path: Path) -> subprocess.CompletedProcess[bytes]:
    """Run oracle on a single file and return the completed process."""
    return subprocess.run([oracle, str(path)], capture_output=True)


def load_fixture_meta(path: Path) -> dict | None:
    meta_path = path.with_suffix(".json")
    if not meta_path.is_file():
        return None
    try:
        return json.loads(meta_path.read_text())
    except Exception:
        return None


def fixture_annotation(path: Path) -> str:
    meta = load_fixture_meta(path)
    if not meta:
        return ""
    items = meta.get("vulnerable_when")
    if not isinstance(items, list) or not items:
        return ""
    members = []
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("member"), str):
            members.append(item["member"])
    if not members:
        return ""
    return f" [vulnerable_when: {', '.join(members)}]"


def stream_members(stdout: bytes) -> list[str]:
    members: list[str] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("member"), str):
            members.append(obj["member"])
    return members


def fixture_vulnerability(path: Path, stdout: bytes) -> str | None:
    meta = load_fixture_meta(path)
    if not meta:
        return None

    members = set(stream_members(stdout))

    items = meta.get("vulnerable_when")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("member"), str):
                if item["member"] in members:
                    return "vulnerable"

    missing = meta.get("vulnerable_when_not")
    if isinstance(missing, list):
        for item in missing:
            if isinstance(item, dict) and isinstance(item.get("member"), str):
                if item["member"] not in members:
                    return "vulnerable"

    return None


def vuln_label(index: int) -> str:
    label = ""
    n = index
    while True:
        label = chr(ord("A") + (n % 26)) + label
        n = n // 26 - 1
        if n < 0:
            break
    return f"vuln: {label}"


def corpus_files(subdir: Path) -> list[Path]:
    return [path for path in sorted(subdir.iterdir()) if path.suffix != ".json"]


def infer_category(path: Path) -> str | None:
    if path.parent.name in ("accept", "reject", "iffy", "malicious"):
        return path.parent.name
    return None


def expected_for_category(category: str | None, no_judgement: bool) -> int | None:
    if category == "accept":
        return 0
    if category == "reject":
        return 1
    if category in ("iffy", "malicious"):
        return None if no_judgement else 1
    return None


def collect_tasks(corpus: Path, no_judgement: bool) -> list[tuple[str, int | None, Path]]:
    if corpus.is_file():
        if corpus.suffix == ".json":
            return []
        category = infer_category(corpus)
        return [(category or "file", expected_for_category(category, no_judgement), corpus)]

    tasks: list[tuple[str, int | None, Path]] = []
    for category in ("accept", "reject", "iffy", "malicious"):
        subdir = corpus / category
        if not subdir.is_dir():
            continue
        expected = expected_for_category(category, no_judgement)
        for path in corpus_files(subdir):
            tasks.append((category, expected, path))
    return tasks


def failure_kind(category: str, expected: int | None, result: subprocess.CompletedProcess[bytes], path: Path) -> str:
    if result.returncode == 0 and fixture_vulnerability(path, result.stdout):
        return vuln_label(0)
    if result.returncode >= 2:
        return "ERROR"
    return "FAIL"


def oracle_status(result: subprocess.CompletedProcess[bytes], path: Path, vuln_label_text: str | None = None) -> str:
    if result.returncode >= 2:
        return "error"
    if result.returncode != 0:
        return "reject"
    if fixture_vulnerability(path, result.stdout):
        return vuln_label_text or "vuln: A"
    return "accept"


def vuln_label_for_result(result: subprocess.CompletedProcess[bytes]) -> str:
    return hashlib.sha256(result.stdout).hexdigest()


def output_hash_for_result(result: subprocess.CompletedProcess[bytes]) -> str:
    return hashlib.sha256(result.stdout).hexdigest()


HASH_COLORS = [
    "\033[38;5;196m",
    "\033[38;5;202m",
    "\033[38;5;220m",
    "\033[38;5;82m",
    "\033[38;5;45m",
    "\033[38;5;141m",
    "\033[38;5;213m",
    "\033[38;5;51m",
]


def table_mode(oracles: list[str], corpus: Path, no_judgement: bool, show_hash: bool) -> None:
    """Run all oracles against all corpus files and print a disagreement matrix."""
    tasks = collect_tasks(corpus, no_judgement)

    if not tasks:
        print("No test files found.")
        return

    # Run all oracles on all files in parallel
    # results[oracle_idx][task_idx] = completed process
    n_oracles = len(oracles)
    n_tasks = len(tasks)
    results: list[list[subprocess.CompletedProcess[bytes] | None]] = [[None] * n_tasks for _ in range(n_oracles)]

    with ThreadPoolExecutor() as executor:
        future_to_idx = {}
        for oi, oracle in enumerate(oracles):
            for ti, (category, expected, path) in enumerate(tasks):
                fut = executor.submit(run_oracle_on_file, oracle, path)
                future_to_idx[fut] = (oi, ti)
        for fut in as_completed(future_to_idx):
            oi, ti = future_to_idx[fut]
            results[oi][ti] = fut.result()

    # Determine which rows to show: any oracle is vulnerable, or oracles disagree with each other.
    display_rows: list[tuple[str, int | None, Path, list[str]]] = []
    for ti, (category, expected, path) in enumerate(tasks):
        row_results = [results[oi][ti] for oi in range(n_oracles)]
        vuln_hashes = sorted({
            vuln_label_for_result(result)
            for result in row_results
            if result is not None and fixture_vulnerability(path, result.stdout)
        })
        vuln_labels = {
            digest: vuln_label(i)
            for i, digest in enumerate(vuln_hashes)
        }

        statuses = []
        for result in row_results:
            if result is None:
                statuses.append("reject")
            elif show_hash and result.returncode == 0:
                statuses.append(output_hash_for_result(result))
            else:
                statuses.append(
                    oracle_status(
                        result,
                        path,
                        vuln_labels.get(vuln_label_for_result(result)) if result is not None else None,
                    )
                )
        if (len(set(statuses)) <= 1
                and not any(sym.startswith("vuln: ") for sym in statuses)
                and not any(sym == "error" for sym in statuses)):
            continue
        display_rows.append((category, expected, path, statuses))

    # Per-category tally (used whether or not there are disagreements)
    category_total: dict[str, int] = {}
    category_shown: dict[str, int] = {}
    for cat, _, _ in tasks:
        category_total[cat] = category_total.get(cat, 0) + 1
    for cat, _, _, _ in display_rows:
        category_shown[cat] = category_shown.get(cat, 0) + 1

    if not display_rows:
        parts = [
            f"{cat}: {n} file{'s' if n != 1 else ''}, {'all accept' if cat == 'accept' else 'all reject'}"
            for cat in ("accept", "iffy", "malicious", "reject")
            if (n := category_total.get(cat, 0)) > 0
        ]
        print("All oracles agree: " + ", ".join(parts))
        return

    _GREEN = "\033[32m"
    _RED = "\033[31m"
    _RESET = "\033[0m"

    _FUCHSIA = "\033[38;5;201m"

    def fmt_sym(sym: str, width: int) -> str:
        pad = " " * (width - len(sym))
        if sym == "accept":
            return f"{_GREEN}{sym}{_RESET}{pad}"
        if sym == "reject":
            return f"{_RED}{sym}{_RESET}{pad}"
        if sym == "error":
            return f"{_FUCHSIA}{sym}{_RESET}{pad}"
        if sym.startswith("vuln: "):
            return f"\033[1;33m{sym}{_RESET}{pad}"
        if show_hash:
            return f"{sym}{pad}"
        return sym + pad

    # Compute column widths from the actual content shown.
    names = [oracle_display_name(o) for o in oracles]
    col_widths: list[int] = []
    for oi, name in enumerate(names):
        width = len(name)
        for _, _, _, symbols in display_rows:
            width = max(width, 8 if show_hash and symbols[oi] != "reject" else len(symbols[oi]))
        col_widths.append(width)

    label_width = max(len(f"{cat}/{path.name}") for cat, _, path, _ in display_rows)

    # Header
    header_label = " " * label_width
    header_cols = "  ".join(n.ljust(col_widths[i]) for i, n in enumerate(names))
    print(f"{header_label}  {header_cols}".rstrip())

    def fmt_label(category: str, filename: str, width: int) -> str:
        plain = f"{category}/{filename}"
        pad = " " * (width - len(plain))
        color = _GREEN if category == "accept" else _RED
        return f"{color}{category}{_RESET}/{filename}{pad}"

    def fmt_hash(sym: str, color: str, width: int) -> str:
        short = sym[:8]
        label = short
        pad = " " * (width - len(label))
        return f"{color}{label}{_RESET}{pad}"

    # Rows
    for category, expected, path, symbols in display_rows:
        label = fmt_label(category, path.name, label_width)
        if show_hash:
            unique_hashes = sorted({sym for sym in symbols if sym != "reject"})
            hash_colors = {h: HASH_COLORS[i % len(HASH_COLORS)] for i, h in enumerate(unique_hashes)}
            row_cols = "  ".join(
                fmt_hash(sym, hash_colors.get(sym, _RED if sym == "reject" else _GREEN), col_widths[i])
                if sym != "reject"
                else fmt_sym(sym, col_widths[i])
                for i, sym in enumerate(symbols)
            )
        else:
            row_cols = "  ".join(fmt_sym(sym, col_widths[i]) for i, sym in enumerate(symbols))
        print(f"{label}  {row_cols}".rstrip())

    # Footer: categories where every file agreed (not shown in the table above)
    quiet = [
        f"{cat}: {n} file{'s' if n != 1 else ''}, {'all accept' if cat == 'accept' else 'all reject'}"
        for cat in ("accept", "iffy", "malicious", "reject")
        if (n := category_total.get(cat, 0)) > 0 and cat not in category_shown
    ]
    if quiet:
        print("\nnot shown: " + "  ".join(quiet))


def main() -> None:
    args = sys.argv[1:]
    if any(a in ("-h", "--help", "help") for a in args) or not args:
        print(USAGE)
        return

    no_judgement = "--no-judgement" in args
    table = "--table" in args
    show_hash = "--hash" in args
    args = [a for a in args if a not in ("--no-judgement", "--table", "--hash")]

    if table:
        if len(args) < 2:
            sys.exit(
                f"Usage: {sys.argv[0]} --table [--no-judgement] <oracle> [<oracle> ...] <corpus|file>"
            )
        oracles = [oracle for oracle in args[:-1] if not is_helper_oracle(oracle)]
        if not oracles:
            sys.exit("No oracle files found.")
        corpus = Path(args[-1])
        table_mode(oracles, corpus, no_judgement, show_hash)
        return

    if len(args) != 2:
        sys.exit(f"Usage: {sys.argv[0]} [--no-judgement] <oracle> <corpus|file>")

    oracle, corpus = args[0], Path(args[1])
    if is_helper_oracle(oracle):
        sys.exit("No oracle files found.")

    tasks = collect_tasks(corpus, no_judgement)
    if not tasks:
        print("No test files found.")
        sys.exit(1)

    total_pass = 0
    total_fail = 0
    group_lines: list[str] = []
    current_category: str | None = None
    current_expected: int | None = None
    current_count = 0
    current_failures: list[tuple[str, subprocess.CompletedProcess[bytes], Path]] = []

    def flush_group() -> None:
        nonlocal total_pass, total_fail, current_category, current_expected, current_count, current_failures
        if current_category is None:
            return
        if current_expected is None:
            group_lines.append(f"{current_category:12s} ({current_count} files, no judgement)")
            for name, result, path in current_failures:
                kind = vuln_label(0) if fixture_vulnerability(path, result.stdout) else "INFO"
                group_lines.append(f"  {kind:7s} {name}  (exited {result.returncode})")
        else:
            n_pass = current_count - len(current_failures)
            total_pass += n_pass
            total_fail += len(current_failures)
            tick = "" if current_failures else " ✓"
            group_lines.append(f"{current_category:12s} {n_pass}/{current_count}{tick}")
            for name, result, path in current_failures:
                kind = failure_kind(current_category, current_expected, result, path)
                group_lines.append(f"  {kind:7s} {name}  (want {current_expected}, got {result.returncode})")
                if result.stderr:
                    for line in result.stderr.decode(errors="replace").splitlines():
                        group_lines.append(f"        {line}")

    for path_category, expected, path in tasks:
        if current_category != path_category:
            flush_group()
            if current_category is not None:
                group_lines.append("")
            current_category = path_category
            current_expected = expected
            current_count = 0
            current_failures = []

        current_count += 1
        result = subprocess.run([oracle, str(path)], capture_output=True)
        vuln = result.returncode == 0 and fixture_vulnerability(path, result.stdout)
        # Exit code >= 2 is an oracle-side error (e.g. permission denied), never
        # counted as a correct rejection regardless of the expected exit code.
        is_error = result.returncode >= 2
        if expected is None:
            current_failures.append((path.name, result, path))
        elif is_error or result.returncode != expected or vuln:
            current_failures.append((path.name, result, path))

    flush_group()

    if group_lines:
        print("\n".join(group_lines))

    total = total_pass + total_fail
    print(f"\n{'total':12s} {total_pass}/{total}")
    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()
