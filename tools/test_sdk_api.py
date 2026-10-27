#!/usr/bin/env python3
"""Compile the typed SDK example and negative fixtures only inside a fresh VM.

Host work is limited to snapshotting approved inputs and transporting bounded
artifacts. Application Cargo, macros, and generated metadata execute in the VM.
"""
import argparse
import json
from pathlib import Path
import re
import shlex
import tempfile

from build_vm import (ROOT, MAX_OUTPUT, MAX_CONTRACT, Image, recipe, toolchain,
                      catalog, source_files, run_vm, artifact)


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f"SDK fixture anchor changed: {old!r}")
    return source.replace(old, new, 1)


def replace_first_of_two(source, old, new):
    if source.count(old) != 2:
        raise ValueError(f"SDK fixture anchor changed: {old!r}")
    return source.replace(old, new, 1)


def fixtures(source):
    """Every case must fail for its intended type or template diagnostic."""
    return [
        ("numeric-route-id", replace_once(
            source, "routes::show_task(task.id)", "routes::show_task(1_u64)"),
         "mismatched types"),
        ("wrong-resource-id", replace_once(
            source, "routes::show_task(task.id)",
            "routes::show_task(Id::<Priority>::new(1))"), "mismatched types"),
        ("undeclared-action-field", replace_first_of_two(
            source, "fields(title, details, estimate, priority, completed)",
            "fields(unknown, details, estimate, priority, completed)"),
         "FieldSpec"),
        ("script-element", replace_once(
            source, 'h1 { "Tasks" }', 'script { "Tasks" }'),
         "unsupported document element"),
        ("string-destination", replace_once(
            source, "routes::index()", '"https://attacker.invalid"'),
         "mismatched types"),
        ("wrong-field-control", replace_first_of_two(
            source, "fields.title.text_input(),", "fields.title.checkbox(),"),
         "checkbox"),
        ("read-through-list-query", replace_once(
            source, "let tasks = tasks.fetch();",
            "let _ = tasks.get(Id::<Task>::new(1));\n    let tasks = tasks.fetch();"),
         "ReadQuery"),
    ]


def positive_fixtures(source):
    namespaced = replace_once(source, "pages: [index, show_task],",
                              "pages: [index, show_task, notes::index, crate::tasks::index],")
    namespaced += r"""
mod notes {
    #[noxide::page(path = "/notes")]
    pub fn index() -> noxide::Page {
        noxide::Page::new("Notes", noxide::html! { p { "Notes" } })
    }
}
mod tasks {
    #[noxide::page(path = "/tasks")]
    pub fn index() -> noxide::Page {
        noxide::Page::new("Tasks", noxide::html! { p { "Tasks" } })
    }
}
fn namespaced_links() {
    let _ = routes::notes::index();
    let _ = routes::tasks::index();
}
"""
    inspection = replace_once(source,
        "#[action(update(Task), fields(title, details, estimate, priority, completed), allow = owner, redirect = show_task)]",
        "#[action(update(Task), fields(title, details, estimate, priority, completed), allow = owner, redirect = show_task, inspect = ReadTask, inspect_fields(title))]")
    inspection = replace_once(inspection,
        "actions: [CreateTask, EditTask, DeleteTask],",
        "actions: [CreateTask, EditTask => inspect_edit, DeleteTask],")
    inspection += r"""
fn inspect_edit(submission: noxide::Submission<EditTask>) -> noxide::ActionResult<EditTask> {
    let _original_title: &str = &submission.original().unwrap().title;
    submission.apply()
}
"""
    optional = replace_once(source, "priority: Priority,", "priority: Option<Priority>,")
    optional = replace_once(optional,
        "@if let Some(details) = &task.details { p { (details) } }",
        "p { (&task.details) }")
    return [("namespaced-pages", namespaced),
            ("typed-inspection", inspection),
            ("optional-choice-and-text", optional)]


def positive_commands(cases):
    commands = []
    for name, _ in cases:
        commands.append(f"""cp /src/api-fixtures/{name}.rs src/lib.rs
if ! cargo check --lib --locked --offline --release --target wasm32-unknown-unknown -j 2 > /tmp/api-diagnostic 2>&1; then
    cat /tmp/api-diagnostic
    echo 'Unexpected SDK compile failure: {name}'
    exit 1
fi
echo 'NOXIDE_API_PASS_OK={name}'
""")
    commands.append("cp /src/examples/private-notes/src/lib.rs src/lib.rs\n")
    return "".join(commands)


def fixture_commands(cases):
    command = []
    for name, _, diagnostic in cases:
        command.append(f"""cp /src/api-fixtures/{name}.rs src/lib.rs
if cargo check --lib --locked --offline --release --target wasm32-unknown-unknown -j 2 > /tmp/api-diagnostic 2>&1; then
    echo 'Unexpected SDK compile success: {name}'
    exit 1
fi
diagnostic=$(cat /tmp/api-diagnostic)
case "$diagnostic" in
    *{shlex.quote(diagnostic)}*) echo 'NOXIDE_API_FIXTURE_OK={name}' ;;
    *) cat /tmp/api-diagnostic; echo 'Wrong diagnostic: {name}'; exit 1 ;;
esac
""")
    command.append("cp /src/examples/private-notes/src/lib.rs src/lib.rs\n")
    return "".join(command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, default=Path.home() / ".cargo")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    image = Image()
    toolchain(image, args.toolchain.resolve())
    catalog(image, args.cargo_home)
    for name in ("noxide", "noxide-protocol", "noxide-macros"):
        crate = ROOT / "crates" / name
        image.add(f"src/crates/{name}/Cargo.toml", (crate / "Cargo.toml").read_bytes())
        for folder in ("src", "wit"):
            if (crate / folder).is_dir():
                source_files(image, crate / folder, f"src/crates/{name}/{folder}")
    workspace = (ROOT / "Cargo.toml").read_text().replace(
        '    "crates/noxide-cli",\n', '').replace('    "crates/noxide-host",\n', '')
    image.add("src/Cargo.toml", workspace.encode())
    image.add("src/README.md", (ROOT / "README.md").read_bytes())
    source = ROOT / "examples/task-board"
    source_files(image, source, "src/examples/private-notes")
    baseline = (source / "src/lib.rs").read_text()
    cases = fixtures(baseline)
    passing = positive_fixtures(baseline)
    for name, content in passing:
        image.add(f"src/api-fixtures/{name}.rs", content.encode())
    for name, content, _ in cases:
        image.add(f"src/api-fixtures/{name}.rs", content.encode())
    init, build = recipe(name="task_board", metadata=True)
    image.add("init", init.encode(), 0o755)
    image.add("build-command", (build + positive_commands(passing) + fixture_commands(cases)).encode(), 0o755)
    print("Building task-board and checking typed API failures in a fresh VM...", flush=True)
    with tempfile.TemporaryDirectory(prefix="noxide-sdk-api-") as folder:
        initrd = Path(folder) / "input.cpio.gz"
        image.write(initrd)
        output = run_vm(args.kernel, initrd, args.output / "build.log", 600)
    if re.findall(rb"(?m)^NOXIDE_BUILD_STATUS=(\d+)$", output) != [b"0"]:
        raise ValueError("SDK fixture VM failed; inspect sanitized build.log")
    compiled = re.findall(rb"(?m)^NOXIDE_API_PASS_OK=([a-z-]+)$", output)
    if compiled != [name.encode() for name, _ in passing]:
        raise ValueError("missing or ambiguous SDK compile-pass results")
    completed = re.findall(rb"(?m)^NOXIDE_API_FIXTURE_OK=([a-z-]+)$", output)
    expected = [name.encode() for name, _, _ in cases]
    if completed != expected:
        raise ValueError("missing or ambiguous SDK fixture results")
    wasm = artifact(output, "WASM", MAX_OUTPUT)
    if not wasm.startswith(b"\0asm\x01\0\0\0"):
        raise ValueError("SDK example did not emit portable Wasm")
    contract = artifact(output, "CONTRACT", MAX_CONTRACT)
    if not isinstance(json.loads(contract), dict):
        raise ValueError("SDK contract must be an object")
    (args.output / "task_board.wasm").write_bytes(wasm)
    (args.output / "manifest.json").write_bytes(contract)
    (args.output / "Cargo.lock").write_bytes(artifact(output, "LOCK", 131072))
    (args.output / "fixtures.json").write_text(json.dumps({"compile_pass": [name for name, _ in passing],
                "compile_fail": [name for name, _, _ in cases]}, indent=2) + "\n")
    print(f"Typed SDK example, {len(passing)} compile-pass and {len(cases)} compile-fail fixtures passed.")


if __name__ == "__main__":
    main()
