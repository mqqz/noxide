#!/usr/bin/env python3
"""Run a cargo test command; retry each failed test once in isolation.

Shared CI runners can push production request deadlines past their bounds under
load. A retried test must pass on its own; the original failure stays in the log
and is summarized, and any test that fails twice fails the job.
"""
import re
import subprocess
import sys


def main():
    if "--" not in sys.argv[1:]:
        sys.exit("usage: rerun_failed_tests.py CARGO_TEST_ARGS -- TEST_HARNESS_ARGS")
    split = sys.argv.index("--")
    cargo, harness = sys.argv[1:split], sys.argv[split + 1:]
    process = subprocess.Popen(["cargo", "test", *cargo, "--", *harness],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    failed = []
    for line in process.stdout:
        sys.stdout.write(line)
        match = re.match(r"test (\S+) \.\.\. FAILED$", line.rstrip())
        if match:
            failed.append(match.group(1))
    if process.wait() == 0:
        return
    # Retry only ordinary test failures; a build or harness failure is final.
    if not failed:
        sys.exit("cargo test failed before reporting a test failure")
    keep = [arg for arg in harness if arg.startswith("--") and arg != "--skip" and not arg.startswith("--test-threads")]
    still = []
    for name in failed:
        print(f"::warning::retrying {name} once in isolation", flush=True)
        if subprocess.run(["cargo", "test", *cargo, "--", *keep, "--exact", name, "--test-threads=1"]).returncode:
            still.append(name)
    print(f"retried {len(failed)} failed test(s): {', '.join(failed)}", flush=True)
    if still:
        sys.exit(f"failed again in isolation: {', '.join(still)}")


if __name__ == "__main__":
    main()
