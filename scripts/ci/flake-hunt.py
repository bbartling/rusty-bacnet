#!/usr/bin/env python3
"""Helpers for the flake hunt, .github/workflows/flake-hunt.yml (docs/ci.md,
"Flake hunt").

  settings       check the run's settings and write them as step outputs
  begin          start a hunt job's records, for a job that stops early
  python-rounds  run the Python suite N times and record each failing test
  nextest        record the failing tests of a nextest stress run from its log
  report         write the issue text from every hunt job's records

Each hunt job keeps its records in one directory: status.json, what the job
ran, and failures.jsonl, one JSON object per failing test and round or
iteration. Test names come from test output, so they travel only in these
files and reach the issue inside a code block, never a shell command.
"""

import argparse
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# unittest prints each failure under a line of 70 "=", headed
# "FAIL: test_x (module.Class.test_x)". -v prints "test_x (module.Class.test_x)"
# as each test starts.
SEPARATOR = "=" * 70
HEADING = re.compile(r"^(FAIL|ERROR|UNEXPECTED SUCCESS): (.+)$")
STARTED = re.compile(r"^\s*(\w+ \([\w.]+\))")
RAN = re.compile(r"^Ran \d+ tests? in ")

# A nextest status line in a stress run, after the colour codes are removed:
#   "     TIMEOUT [ 120.003s] [3/20] ( 17/3527) bacnet-server server::x::y"
# The iteration is "[3]" under --stress-duration.
NEXTEST_LINE = re.compile(
    r"^\s*(?P<status>[A-Z][A-Z0-9 -]*?)\s+\[[^\]]*\]\s+"
    r"\[(?P<iteration>\d+(?:/\d+)?)\]\s+\(\s*\d+/\d+\)\s+"
    r"(?P<binary>\S+)\s+(?P<test>\S+)\s*$"
)
NEXTEST_FAILED = re.compile(r"FAIL|TIMEOUT|^SIG|ABORT")
NEXTEST_SUMMARY = re.compile(r"^\s*Summary \[[^\]]*\]\s+(.*stress run iterations.*)$")


def plain(text):
    return ANSI.sub("", text)


def write_json(path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def append_records(out, records):
    with open(out / "failures.jsonl", "a", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def step_summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")


def fail(message):
    print(f"::error::{message}")
    sys.exit(1)


# settings ---------------------------------------------------------------


def settings(_args):
    """Check PYTHON_ROUNDS, STRESS_DURATION and STRESS_COUNT, then write the
    step outputs, with each hunt job's timeout sized to fit them."""
    rounds = os.environ.get("PYTHON_ROUNDS", "").strip()
    duration = os.environ.get("STRESS_DURATION", "").strip()
    count = os.environ.get("STRESS_COUNT", "").strip()
    if not re.fullmatch(r"[0-9]+", rounds) or not 1 <= int(rounds) <= 300:
        fail(f"python_rounds must be a whole number from 1 to 300, not {rounds!r}")
    rounds = int(rounds)
    # Room for the setup and build, and about 2 minutes a round, which covers
    # a slow macOS host; python-rounds stops early rather than overrun it.
    python_timeout = min(360, max(60, 20 + 2 * rounds))
    if count:
        if not re.fullmatch(r"[0-9]+", count) or not 1 <= int(count) <= 1000:
            fail(f"stress_count must be a whole number from 1 to 1000, not {count!r}")
        flag, value = "--stress-count", count
        # About 3 minutes an iteration at most on a hosted runner.
        stress_timeout = min(360, max(60, 30 + 3 * int(count)))
        stress = f"{count} iterations"
    else:
        m = re.fullmatch(r"([0-9]+)([smh])", duration)
        minutes = 0
        if m:
            minutes = math.ceil(int(m[1]) * {"s": 1 / 60, "m": 1, "h": 60}[m[2]])
        if not 1 <= minutes <= 300:
            fail(f"stress_duration must be from 1m to 5h, such as 20m or 2h, not {duration!r}")
        flag, value = "--stress-duration", duration
        # The build, the iteration still running when the time is up, and a
        # margin for the slowest test's 2-minute timeout.
        stress_timeout = min(360, max(60, 40 + minutes))
        stress = f"for {duration}"
    outputs = {
        "python_rounds": rounds,
        "python_timeout": python_timeout,
        "stress_flag": flag,
        "stress_value": value,
        "stress_timeout": stress_timeout,
        "description": f"Python suite {rounds} times; nextest stress {stress}",
    }
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
        for name, value in outputs.items():
            f.write(f"{name}={value}\n")
            print(f"{name}={value}")
    step_summary(
        f"**Flake hunt settings:** {outputs['description']} on each platform. "
        f"Job timeouts: {python_timeout} minutes for the Python suite, "
        f"{stress_timeout} for nextest stress."
    )


# begin ------------------------------------------------------------------


def begin(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(
        out / "status.json",
        {"job": args.job, "summary": "stopped before the hunt finished: setup or build failed, or the job was cancelled"},
    )


# python-rounds ----------------------------------------------------------


def run_round(command, log, timeout):
    """Run one round; returns (exit code, whether it hung)."""
    with open(log, "wb") as f:
        proc = subprocess.Popen(command, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        hung = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            hung = True
            # With -X faulthandler, SIGABRT prints every thread's Python stack
            # into the log before the process dies.
            proc.send_signal(signal.SIGABRT)
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                pass
        finally:
            # The round's leftover processes too (servers, openssl).
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()
    return proc.returncode, hung


def python_failures(text, code, hung, timeout):
    """[(status, test)] for one round's output."""
    lines = plain(text).splitlines()
    found = []
    for previous, line in zip([""] + lines, lines):
        m = HEADING.match(line) if previous == SEPARATOR else None
        if m:
            found.append((m[1], m[2]))
    if hung or code < 0 or (code != 0 and not found):
        finished = any(RAN.match(line) for line in lines)
        last = next((m[1] for m in map(STARTED.match, reversed(lines)) if m), None)
        if hung:
            status = f"HANG (killed after {timeout // 60} min)" if timeout >= 60 else f"HANG (killed after {timeout} s)"
        elif code < 0:
            try:
                status = f"CRASH ({signal.Signals(-code).name})"
            except ValueError:
                status = f"CRASH (signal {-code})"
        else:
            status = f"EXIT {code}"
        if finished:
            where = "after the last test, at interpreter exit"
        elif last:
            where = f"in or after {last}"
        else:
            where = "before any test started"
        found.append((status, where))
    return list(OrderedDict.fromkeys(found))


def python_rounds(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        fail("no command after --")
    ran = failed = 0
    stopped = ""
    for n in range(1, args.rounds + 1):
        if args.deadline - time.time() < args.round_timeout:
            stopped = f"; stopped before round {n}, with less than one round's timeout left of the job's"
            print(f"::warning::Stopped after {ran} of {args.rounds} rounds: the next could overrun the job's timeout.")
            break
        log = out / f"round-{n:03d}.log"
        started = time.monotonic()
        code, hung = run_round(command, log, args.round_timeout)
        seconds = time.monotonic() - started
        ran += 1
        found = python_failures(log.read_text(encoding="utf-8", errors="replace"), code, hung, args.round_timeout)
        where = f"round {n}/{args.rounds}"
        if not found:
            print(f"{where}: passed in {seconds:.0f} s", flush=True)
            log.unlink()
            continue
        failed += 1
        append_records(out, [{"job": args.job, "where": where, "status": s, "test": t} for s, t in found])
        print(f"::group::{where}: {len(found)} failing in {seconds:.0f} s (exit {code}); its output")
        print(log.read_text(encoding="utf-8", errors="replace"))
        print("::endgroup::")
        for status, test in found:
            print(f"::error::{where}: {status} {test}")
    summary = f"{ran} of {args.rounds} rounds, {failed} with failures{stopped}"
    write_json(out / "status.json", {"job": args.job, "summary": summary})
    print(summary)
    step_summary(f"**{args.job}:** {summary}.")
    return 1 if failed else 0


# nextest ----------------------------------------------------------------


def nextest_failures(text):
    """([(iteration, status, test)], the stress summary or None)."""
    found, summary = [], None
    for line in plain(text).splitlines():
        m = NEXTEST_LINE.match(line)
        if m and NEXTEST_FAILED.search(m["status"]):
            found.append((m["iteration"], m["status"], f"{m['binary']} {m['test']}"))
            continue
        m = NEXTEST_SUMMARY.match(line)
        if m:
            summary = m[1]
    # The final summary repeats each failure.
    return list(OrderedDict.fromkeys(found)), summary


def nextest(args):
    out = Path(args.out)
    log = Path(args.log)
    text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    found, summary = nextest_failures(text)
    code = args.exit_code.strip()
    records = [{"job": args.job, "where": f"iteration {i}", "status": s, "test": t} for i, s, t in found]
    if not code:
        note = "nextest did not finish (the job timed out or was cancelled)"
        records.append({"job": args.job, "where": "stress run", "status": "INTERRUPTED", "test": "(see the job log)"})
    elif code != "0" and not found:
        note = f"nextest exited {code} without a failing test"
        what = "build failed" if code == "101" else f"exit {code}"
        records.append({"job": args.job, "where": "stress run", "status": what.upper(), "test": "(see the job log)"})
    else:
        note = summary or f"nextest exited {code}"
    if records:
        append_records(out, records)
        for r in records:
            print(f"::error::{r['where']}: {r['status']} {r['test']}")
    write_json(out / "status.json", {"job": args.job, "summary": note})
    print(note)
    step_summary(f"**{args.job}:** {note}.")
    # The stress step's own exit code fails the job.
    return 0


# report -----------------------------------------------------------------


def safe(text, limit=300):
    """Test output made safe for a line in a code block."""
    text = CONTROL.sub(" ", plain(str(text))).replace("`", "'")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def cell(text):
    return safe(text, 200).replace("|", "/")


def occurrences(wheres):
    """["iteration 2", "iteration 5"] -> "2 times: iterations 2, 5"."""
    words = {w.split(" ", 1)[0] for w in wheres}
    if len(wheres) == 1 or len(words) != 1 or not all(" " in w for w in wheres):
        listed = ", ".join(wheres)
    else:
        listed = f"{words.pop()}s " + ", ".join(w.split(" ", 1)[1] for w in wheres)
    return listed if len(wheres) == 1 else f"{len(wheres)} times: {listed}"


def report(args):
    results = Path(args.results)
    statuses, records = [], []
    for directory in sorted(p for p in results.glob("*") if p.is_dir()) if results.is_dir() else []:
        status = directory / "status.json"
        if status.exists():
            statuses.append(json.loads(status.read_text(encoding="utf-8")))
        failures = directory / "failures.jsonl"
        if failures.exists():
            records += [json.loads(line) for line in failures.read_text(encoding="utf-8").splitlines() if line.strip()]
    needs = json.loads(os.environ.get("NEEDS") or "{}")
    env = os.environ.get
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"### Flake hunt, {when}",
        "",
        f"- Run: {env('RUN_URL', '?')}",
        f"- Commit: `{cell(env('COMMIT', '?'))}` ({cell(env('EVENT', '?'))} on `{cell(env('REF', '?'))}`)",
        f"- Settings: {cell(env('SETTINGS', '?'))}",
        "- Jobs: " + ", ".join(f"{cell(k)} {cell(v.get('result'))}" for k, v in sorted(needs.items())),
        "",
        "| Job | Result |",
        "| --- | --- |",
    ]
    lines += [f"| {cell(s.get('job'))} | {cell(s.get('summary'))} |" for s in statuses]
    if not statuses:
        lines.append("| (none) | no hunt job left results |")

    groups = OrderedDict()
    for r in records:
        groups.setdefault((r.get("job"), r.get("status"), r.get("test")), []).append(r.get("where"))
    lines.append("")
    if groups:
        lines += ["Failing tests, with the round or stress iteration of each failure:", "", "```text"]
        # GitHub takes up to 65,536 characters in an issue or comment.
        size, shown = sum(len(line) + 1 for line in lines), 0
        for (job, status, test), wheres in groups.items():
            entry = [f"{safe(job)} | {safe(status)} | {safe(test)}", f"    {safe(occurrences(wheres), 400)}"]
            size += sum(len(line) + 1 for line in entry)
            if shown == args.max_groups or size > 50_000:
                break
            lines += entry
            shown += 1
        lines.append("```")
        if len(groups) > shown:
            lines.append(f"\n{len(groups) - shown} more; see the run.")
    else:
        lines.append("No failing test was recorded; see the run for the failed job's log.")
    body = "\n".join(lines) + "\n"

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "comment.md").write_text(body, encoding="utf-8")
    intro = (
        "The nightly flake hunt (`.github/workflows/flake-hunt.yml`, see "
        f"[docs/ci.md]({env('DOCS_URL', 'docs/ci.md')})) runs the Python suite and nextest "
        "stress runs over and over to catch rare failures. It opened this issue for the "
        "failures below, and later failing runs comment here while it stays open. Close it "
        "once they are fixed or filed; the next failure opens a new one.\n\n"
    )
    (out / "issue.md").write_text(intro + body, encoding="utf-8")
    # Not the text itself: this job can write issues, and test output stays
    # out of its log. The next step puts the text in the job summary.
    print(f"{len(statuses)} job results, {len(records)} failures in {len(groups)} groups; {len(body)} characters")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command_name", required=True)
    sub.add_parser("settings")
    p = sub.add_parser("begin")
    p.add_argument("--job", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("python-rounds")
    p.add_argument("--job", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--rounds", type=int, required=True)
    p.add_argument("--round-timeout", type=int, required=True, help="seconds")
    p.add_argument("--deadline", type=int, required=True, help="Unix time to finish by")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- the suite's command")
    p = sub.add_parser("nextest")
    p.add_argument("--job", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--exit-code", required=True, help="nextest's exit code, empty if it didn't finish")
    p = sub.add_parser("report")
    p.add_argument("--results", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--max-groups", type=int, default=100)
    args = parser.parse_args()
    handler = {
        "settings": settings,
        "begin": begin,
        "python-rounds": python_rounds,
        "nextest": nextest,
        "report": report,
    }[args.command_name]
    sys.exit(handler(args) or 0)


if __name__ == "__main__":
    main()
