#!/usr/bin/env python3
"""Compile typed SDK fixtures locally (--local) or inside a fresh VM.

Local mode is only for trusted fixtures and dependencies. Both backends test
identical generated metadata, compile-pass cases, and compile-fail diagnostics.
"""
import argparse
from build_local import run_local
from build_recipe import emission
from build_vm import rewrite_sdk_path
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

from build_vm import (ROOT, DEFAULT_VM_SECONDS, MAX_OUTPUT, MAX_CONTRACT, Image,
                      recipe, toolchain, catalog, source_files, run_vm, artifact,
                      check_build_status)


EQUIVALENT_APPS = ("private-notes", "task-board", "public-articles", "policy-board", "repeated", "forum")
ADMISSION_FAILURES = {
    "notes-added-field": b"creation requires every writable field",
    "notes-renamed-field": b"creation requires every writable field",
    "policy-board-cross-resource-form": b"mutation form requires its record route",
    "policy-board-public-forms": b"public routes cannot have forms",
}


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


def convenience_fixtures():
    passing = []
    comparisons = []
    for app in EQUIVALENT_APPS:
        for variant, path in (
            ("simple", (ROOT / "tools/fixtures/sdk" / (app + "-simple.rs")) if app in ("policy-board", "repeated", "forum") else (ROOT / "tools/fixtures/queries/public-articles.rs" if app == "public-articles" else ROOT / "examples" / app / "src/lib.rs")),
            ("explicit", ROOT / "tools/fixtures/sdk" / (app + "-explicit.rs")),
        ):
            name = app + "-" + variant
            passing.append((name, path.read_text()))
            comparisons.append(name)
    for variant, path in (("simple", ROOT / "examples/forum/src/lib.rs"),
                          ("explicit", ROOT / "tools/fixtures/sdk/forum-layout-explicit.rs")):
        name = "forum-layout-" + variant
        passing.append((name, path.read_text()))
        comparisons.append(name)
    notes = passing[0][1]
    start = notes.index('    #[page("/")]')
    middle = notes.index('    #[page("/notes/{note}")]')
    end = notes.index('    crud!')
    reordered = notes[:start] + notes[middle:end] + notes[start:middle] + notes[end:]
    explicit_hooks = notes[:end] + """
    #[action(create(Note), fields(body), allow = owner, redirect = show_note)]
    struct CreateNote;
    #[action(update(Note), fields(body), allow = owner, redirect = show_note)]
    struct EditNote;
    #[action(delete(Note), allow = owner, redirect = index)]
    struct DeleteNote;
    hooks! {
        CreateNote { handler(create_note) }
        EditNote { handler(edit_note), layout(note_editor) }
    }
}
"""
    variants = [
        ("notes-reordered", reordered),
        ("notes-explicit-hooks", explicit_hooks),
        ("notes-qualified-pages", notes.replace('#[page(', '#[noxide::page(')),
        ("notes-relocated", 'include!("../../../api-fixtures/private-notes-simple.rs");\n'),
        ("notes-explicit-policy", notes.replace("redirect(show_note)", "redirect(show_note), allow = owner")),
        ("notes-role-policy", notes.replace("redirect(show_note)", 'redirect(show_note), allow = role("writer")')),
        ("notes-added-field", notes.replace("        body: String,", '        body: String,\n        #[field(max_bytes = 128)]\n        extra: String,')),
        # Keep explicit writable fields stable while changing an inferred read-only key.
        ("notes-renamed-field", notes.replace("        body: String,", '        body: String,\n        #[field(max_bytes = 128)]\n        renamed: String,')),
    ]
    policy = dict(passing)["policy-board-simple"]
    prefix, *items = policy.rsplit("\n}", 1)[0].split("    // item\n")
    reordered_policy = prefix + "".join("    // item\n" + item for item in reversed(items)) + "\n}\n"
    unbound = replace_once(policy, "posts: Query<PublishedPosts>, create: Form<CreatePost>", "posts: Query<PublishedPosts>")
    start = unbound.index("    fn posts(")
    end = unbound.index("    // item", start)
    unbound = unbound[:start] + unbound[start:end].replace("                (create)\n", "") + unbound[end:]
    audit = policy.rsplit("\n}", 1)[0] + '''
    #[query(list(TeamNote), allow = all(same_tenant, role("auditor")))]
    struct AuditNotes;
    #[page("/audit")]
    fn audit(mut notes: Query<AuditNotes>) -> Page {
        Page::new("Audit", html! { main { @for note in notes.fetch() { p { (&note.body) } } } })
    }
}
'''
    variants += [
        ("policy-board-reordered", reordered_policy),
        ("policy-board-unbound-create", unbound),
        ("policy-board-added-query", audit),
        ("policy-board-cross-resource-form", replace_once(policy, "edit: Form<EditTeamNote>", "edit: Form<EditSetting>")),
        ("policy-board-public-forms", replace_once(policy, 'path = "/posts", access = public_optional', 'path = "/posts", access = public')),
        ("notes-raw-action-simple", notes.replace("EditNote", "r#EditNote")),
        ("notes-raw-action-explicit", dict(passing)["private-notes-explicit"].replace("EditNote", "r#EditNote")),
        ("notes-qualified-capabilities", notes.replace("List<Note>", "noxide::List<Note>").replace("Read<Note>", "noxide::Read<Note>")),
        ("notes-nested-helper", notes.rsplit("\n}", 1)[0] + '''
    mod helper {
        #[noxide::page(path = "/unregistered")]
        pub fn hidden() -> noxide::Page { noxide::Page::new("Hidden", noxide::html! { p { "Hidden" } }) }
    }
}
'''),
    ]
    repeated = dict(passing)["repeated-simple"]
    prefix, block = repeated.split("    // actions\n", 1)
    entries = block.splitlines()[1:-2]
    assert len(entries) == 7 and all(entry.strip().startswith(("create ", "update ", "delete ")) for entry in entries), "repeated fixture structure changed"
    reordered_repeated = prefix + "    // actions\n" + "".join(
        "    crud! { Reply {\n" + entry + "\n    } }\n" for entry in reversed(entries)) + "}\n"
    variants += [("repeated-reordered", reordered_repeated)]
    passing += variants
    comparisons += [name for name, _ in variants]
    public = dict(passing)["public-articles-simple"]
    initial = notes.replace("        body: String,", '        body: String,\n        #[field(initial = true)]\n        published: bool,')
    initial_input = initial.rsplit("\n}", 1)[0] + """
    fn forbidden_input(s: Submission<CreateNote>) { let _ = s.input().published; }
}
"""
    initial_form = initial.rsplit("\n}", 1)[0] + """
    fn forbidden_form(f: FormFields<CreateNote>) { let _ = f.published; }
}
"""
    failures = [
        ("initial-create-input", initial_input, "no field"),
        ("initial-create-form", initial_form, "no field"),
        ("unscoped-shorthand", notes.replace('key = "notes", owner', 'key = "notes"'), "owner resource"),
        ("external-app", '#[noxide::app] mod notes;', "app requires an inline module"),
        ("query-collision", notes.replace('    crud!', '    struct __Noxide_list_Note;\n    crud!'), "generated query name collision"),
        ("conditional-page", notes.replace('    #[page("/")]', '    #[cfg(any())]\n    #[page("/")]'), "conditional application declarations"),
        ("conditional-field", notes.replace('        body: String,', '        #[cfg(any())]\n        body: String,'), "conditional application declarations"),
        ("conditional-hook", notes.replace('    fn edit_note(', '    #[cfg(any())]\n    fn edit_note('), "conditional application declarations"),
        ("missing-crud-fields", notes.replace('fields(body), redirect(show_note), handler(create_note)', 'redirect(show_note), handler(create_note)'), "explicit fields"),
        ("unprojected-public-field", public.replace('(&article.body)', '(&article.private_notes)'), "no field"),
        ("public-without-projection", public.replace(', fields(title, body)', ''), "public queries require"),
    ]
    failures += [
        ("foreign-list-type", notes.replace("List<Note>", "other::List<Note>"), "read shorthand must use"),
        ("nonowner-crud-without-policy", policy.replace(', allow = all(same_tenant, role("writer"))', ''), "explicit policy or owner resource"),
        ("anonymous-public-update", policy.replace("allow = capability", "allow = public"), "public requires create"),
        ("anonymous-capability-create", replace_once(policy, "allow = public }", "allow = capability }"), "capability requires update or delete"),
        ("composed-public-policy", replace_once(policy, "allow = public }", "allow = any(public, owner) }"), "public or capability cannot appear inside"),
        ("cross-resource-read", replace_once(policy, "mut read: Query<ReadTeamNote>", "mut read: Read<Setting>"), "mismatched types"),
        ("update-projection-exclusion", policy.rsplit("\n}", 1)[0] + '\n fn invalid(fields: FormFields<EditTeamNote>) -> FormLayout { fields.private_hint.text_input() }\n}\n', "no field"),
        ("conditional-crud", notes.replace("    crud!", "    #[cfg(any())]\n    crud!"), "conditional application declarations"),
        ("conditional-attribute", notes.replace('    #[page("/")]', '    #[cfg_attr(all(), inline)]\n    #[page("/")]'), "conditional application declarations"),
        ("duplicate-action-hooks", notes.rsplit("\n}", 1)[0] + '\n hooks! { EditNote { handler(edit_note) } }\n}\n', "declare hooks once"),
    ]
    failures += [
        ("repeated-name-in-block", repeated.replace("create CreateAnonymousReply {", "create CreateReply {"), "generated action name collision"),
        ("repeated-name-across-blocks", reordered_repeated.replace("create CreateAnonymousReply {", "create CreateReply {"), "generated action name collision"),
        ("repeated-name-explicit", repeated.replace("    // actions", "    #[action(create(Reply), fields(body), allow = owner, redirect = reply)] struct CreateReply;\n    // actions"), "generated action name collision"),
        ("repeated-missing-policy", repeated.replace('key = "replies", owner', 'key = "replies"'), "explicit policy or owner resource"),
        ("repeated-delete-fields", repeated.replace("delete DeleteReply {", "delete DeleteReply { fields(body),"), "delete accepts no fields"),
        ("repeated-duplicate-option", repeated.replace("create CreateReply {", "create CreateReply { fields(body),"), "duplicate CRUD option"),
        ("repeated-missing-redirect", repeated.replace("redirect(parent(thread)), handler(create_reply)", "handler(create_reply)"), "requires redirect"),
        ("repeated-wrong-handler", repeated.replace("handler(edit_secret)", "handler(edit_reply)"), "mismatched types"),
        ("repeated-wrong-layout", repeated.replace("layout(secret_layout)", "layout(edit_layout)"), "mismatched types"),
        ("repeated-owner-moderator-field", repeated.rsplit("\n}", 1)[0] + '\n fn forbidden(f: FormFields<r#EditReply>) { let _ = f.published; }\n}\n', "no field"),
        ("repeated-capability-moderator-field", repeated.rsplit("\n}", 1)[0] + '\n fn forbidden(f: FormFields<EditSecret>) { let _ = f.published; }\n}\n', "no field"),
    ]
    query_example = (ROOT / "examples/public-articles/src/lib.rs").read_text()
    passing.append(("public-query-features", query_example))
    failures += [
        ("public-param-disclosure", query_example.replace("disclose(category),", ""), "disclose must name"),
        ("account-route-parameter", query_example.replace("routes::category(Category::Books)", 'routes::category("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse::<noxide::AccountId>().unwrap())'), "ParamValue"),
    ]
    return passing, failures, comparisons


def contract_commands(names):
    commands = []
    for name in names:
        marker = "EQ_" + name.upper().replace("-", "_")
        commands.append(f"""cp /src/api-fixtures/{name}.rs src/lib.rs
cargo run --quiet --locked --offline --release --bin noxide-contract -j 2 > /tmp/equivalence.json
echo NOXIDE_{marker}_BEGIN
base64 /tmp/equivalence.json
echo NOXIDE_{marker}_END
""")
    commands.append("cp /src/examples/private-notes/src/lib.rs src/lib.rs\n")
    return "".join(commands)


def scaffold_inputs(image, host_cli):
    # Generation only writes trusted source. Compilation uses the selected backend.
    with tempfile.TemporaryDirectory(prefix="noxide-starter-input-") as directory:
        project = Path(directory) / "task-board"
        import os
        environment = dict(os.environ, XDG_STATE_HOME=str(Path(directory) / "state"))
        subprocess.run([str(host_cli.resolve()), "new", str(project)], env=environment, check=True, timeout=10)
        source_files(image, project, "src/examples/starter")
        rewrite_sdk_path(image, "src/examples/starter/Cargo.toml")


def scaffold_commands():
    # The two standalone projects intentionally share a crate identity for exact
    # contract comparison. Separate target dirs prevent Cargo artifact reuse.
    return """cd /tmp/work/examples/starter
cargo generate-lockfile --offline
CARGO_TARGET_DIR=/tmp/starter-target cargo build --lib --locked --offline --release --target wasm32-unknown-unknown -j 2
cat >>Cargo.toml <<'STARTER_TARGET'

[[bin]]
name = "noxide-contract"
path = "noxide-contract.rs"
STARTER_TARGET
cat >noxide-contract.rs <<'STARTER_SOURCE'
fn main() { print!("{}", task_board::noxide_manifest()); }
STARTER_SOURCE
CARGO_TARGET_DIR=/tmp/starter-target cargo run --quiet --locked --offline --release --bin noxide-contract -j 2 > /tmp/starter-contract.json
echo NOXIDE_EQ_STARTER_GENERATED_BEGIN
base64 /tmp/starter-contract.json
echo NOXIDE_EQ_STARTER_GENERATED_END
cd /tmp/work/examples/private-notes
"""


def validate_contracts(contracts, comparisons, output_dir, host_cli):
    # Captured from the unmodified PR #15 merge, before implementation moves.
    assert contracts["forum-layout-simple"] == contracts["forum-layout-explicit"], "laid-out forum mismatch"
    frozen = ROOT / "tools/fixtures/sdk/baseline"
    for path in sorted(frozen.glob("*.json")):
        if path.name == "approval-hashes.json":
            continue
        assert contracts[path.stem + "-simple"] == json.loads(path.read_text()), path.stem + " frozen contract drift"
    for app in EQUIVALENT_APPS:
        assert contracts[app + "-simple"] == contracts[app + "-explicit"], app + " contract mismatch"
    assert contracts["repeated-simple"] == contracts["repeated-reordered"], "repeated entry/block order changed contract"
    assert contracts["notes-reordered"] == contracts["private-notes-simple"], "item order changed contract"
    for name in ("notes-explicit-hooks", "notes-qualified-pages", "notes-relocated"):
        assert contracts[name] == contracts["private-notes-simple"], name + " changed contract"
    assert contracts["notes-explicit-policy"] == contracts["private-notes-simple"], "explicit owner differs from inferred owner"
    assert contracts["notes-role-policy"] != contracts["private-notes-simple"], "policy change missing from contract"
    assert contracts["notes-added-field"] != contracts["private-notes-simple"], "schema change missing from contract"
    before = contracts["private-notes-simple"]
    after = contracts["notes-added-field"]
    assert before["actions"] == after["actions"], "new field expanded action projections"
    assert before["operations"] == after["operations"], "new field expanded operations"
    assert contracts["notes-renamed-field"]["resources"] != after["resources"], "inferred-key rename missing from schema"
    assert contracts["starter-generated"] == contracts["private-notes-simple"], "starter differs from the reviewed notes app"
    board = contracts["policy-board-simple"]
    assert board == contracts["policy-board-reordered"], "resource/action ordering changed contract"
    assert contracts["notes-raw-action-simple"] == contracts["notes-raw-action-explicit"], "raw action lowering differs"
    for name in ("notes-qualified-capabilities", "notes-nested-helper"):
        assert contracts[name] == contracts["private-notes-simple"], name + " changed registered authority"
    unbound = contracts["policy-board-unbound-create"]
    assert board["actions"] == unbound["actions"]
    assert board["operations"] == unbound["operations"]
    routes = {route["path"]: route for route in board["routes"]}
    unbound_routes = {route["path"]: route for route in unbound["routes"]}
    assert routes["/posts"]["forms"]
    assert unbound_routes["/posts"] == dict(routes["/posts"], forms=[])
    assert routes.keys() == unbound_routes.keys()
    assert board["resources"] == unbound["resources"]
    for path in routes.keys() - {"/posts"}:
        assert routes[path] == unbound_routes[path], "removing a form changed another route"
    audit = contracts["policy-board-added-query"]
    original_ops = {op["id"]: op for op in board["operations"]}
    audit_ops = {op["id"]: op for op in audit["operations"]}
    assert all(audit_ops[identifier] == op for identifier, op in original_ops.items()), "adding a query changed existing authority"
    added = audit_ops.keys() - original_ops.keys()
    assert len(added) == 1 and len(audit["routes"]) == len(board["routes"]) + 1
    assert audit_ops[added.pop()]["policy"] == {"any": [["same_tenant", {"role": {"name": "auditor", "tenant_scoped": False}}]]}
    assert audit["actions"] == board["actions"], "adding a query changed mutations"
    assert audit["resources"] == board["resources"]
    audit_routes = {route["path"]: route for route in audit["routes"]}
    assert all(audit_routes[path] == route for path, route in routes.items()), "adding a query changed existing route grants"
    resource_ids = {resource["name"]: resource["id"] for resource in board["resources"]}
    def mutations(resource):
        return {original_ops[action["operation"]]["kind"]: action for action in board["actions"]
                if original_ops[action["operation"]]["resource"] == resource_ids[resource]}
    def policy_of(action):
        return original_ops[action["operation"]]["policy"]
    guest = mutations("guest_posts")
    assert set(guest) == {"create", "update", "delete"}
    assert policy_of(guest["create"]) == {"any": [["public"]]}
    assert policy_of(guest["update"]) == policy_of(guest["delete"]) == {"any": [["capability"]]}
    assert guest["create"]["fields"] == ["body", "published"]
    assert guest["update"]["fields"] == ["body"] and guest["delete"]["fields"] == []
    tenant = mutations("team_notes")
    assert policy_of(tenant["create"]) == {"any": [["same_tenant", {"role": {"name": "writer", "tenant_scoped": False}}]]}
    assert policy_of(tenant["update"]) == {"any": [["same_tenant", "owner"], ["same_tenant", {"role": {"name": "editor", "tenant_scoped": True}}]]}
    assert policy_of(tenant["delete"]) == {"any": [["same_tenant", {"role": {"name": "admin", "tenant_scoped": True}}]]}
    assert tenant["create"]["fields"] == ["body", "private_hint"] and tenant["update"]["fields"] == ["body"]
    hashes = {}
    for name in comparisons:
        result = subprocess.run([str(host_cli.resolve()), "contract-hash", str(output_dir / (name + ".json"))],
                                capture_output=True, check=False)
        if name in ADMISSION_FAILURES:
            assert result.returncode != 0 and ADMISSION_FAILURES[name] in result.stderr, name + ": unexpected admission result"
        else:
            assert result.returncode == 0, name + ": " + result.stderr.decode(errors="replace")
            hashes[name] = result.stdout.strip().decode("ascii")
    for name, expected in json.loads((frozen / "approval-hashes.json").read_text()).items():
        assert hashes[name + "-simple"] == expected, name + " frozen approval digest drift"
    for app in EQUIVALENT_APPS:
        assert hashes[app + "-simple"] == hashes[app + "-explicit"], app + " approval digest differs"
    assert hashes["repeated-simple"] == hashes["repeated-reordered"], "repeated entry/block order changed digest"
    assert hashes["notes-reordered"] == hashes["private-notes-simple"]
    for name in ("notes-explicit-hooks", "notes-qualified-pages", "notes-relocated"):
        assert hashes[name] == hashes["private-notes-simple"]
    assert hashes["notes-explicit-policy"] == hashes["private-notes-simple"]
    assert hashes["notes-role-policy"] != hashes["private-notes-simple"]
    assert hashes["starter-generated"] == hashes["private-notes-simple"]
    assert hashes["policy-board-simple"] == hashes["policy-board-reordered"]
    assert hashes["notes-raw-action-simple"] == hashes["notes-raw-action-explicit"]
    for name in ("notes-qualified-capabilities", "notes-nested-helper"):
        assert hashes[name] == hashes["private-notes-simple"]
    for name in ("policy-board-unbound-create", "policy-board-added-query"):
        assert hashes[name] != hashes["policy-board-simple"], "changed authority must require reapproval"
    (output_dir / "approval-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
    return hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-cli", type=Path, default=ROOT / "target/debug/noxide",
                        help="trusted host CLI, built before running this test")
    parser.add_argument("--local", action="store_true", help="build trusted code on the host without VM isolation")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--toolchain", type=Path)
    parser.add_argument("--cargo-home", type=Path, default=Path.home() / ".cargo")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.local and (args.kernel is None or args.toolchain is None):
        parser.error("VM builds require --kernel and --toolchain")
    if args.toolchain is None:
        args.toolchain = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    if not args.host_cli.is_file():
        parser.error("build the trusted noxide CLI first, or pass --host-cli")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    image = Image()
    if not args.local:
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
    scaffold_inputs(image, args.host_cli)
    baseline = (ROOT / "tools/fixtures/sdk/task-board-advanced.rs").read_text()
    cases = fixtures(baseline)
    passing = positive_fixtures(baseline)
    convenience, failures, comparisons = convenience_fixtures()
    passing += convenience
    cases += failures
    for name, content in passing:
        image.add(f"src/api-fixtures/{name}.rs", content.encode())
    for name, content, _ in cases:
        image.add(f"src/api-fixtures/{name}.rs", content.encode())
    init, build = recipe(name="task_board", metadata=True)
    image.add("artifact-command", emission(name="task_board", metadata=True).encode())
    image.add("init", init.encode(), 0o755)
    image.add("build-command", (build + scaffold_commands() + positive_commands(passing) + contract_commands(comparisons) + fixture_commands(cases)).encode(), 0o755)
    if args.local:
        output = run_local(image, args.toolchain, args.output / "build.log", DEFAULT_VM_SECONDS)
    else:
        print("Building task-board and checking typed API failures in a fresh VM...", flush=True)
        with tempfile.TemporaryDirectory(prefix="noxide-sdk-api-") as folder:
            initrd = Path(folder) / "input.cpio.gz"
            image.write(initrd)
            output = run_vm(args.kernel, initrd, args.output / "build.log", DEFAULT_VM_SECONDS)
    check_build_status(output)
    comparisons.append("starter-generated")
    contracts = {}
    for name in comparisons:
        raw = artifact(output, "EQ_" + name.upper().replace("-", "_"), MAX_CONTRACT)
        contracts[name] = json.loads(raw)
        (args.output / (name + ".json")).write_bytes(raw)
    validate_contracts(contracts, comparisons, args.output, args.host_cli)
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
    print(f"Generated starter, typed SDK example, {len(passing)} compile-pass and {len(cases)} compile-fail fixtures passed.")


if __name__ == "__main__":
    main()
