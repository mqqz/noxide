# Application API

Noxide applications declare resources and permissions in Rust, render Document IR,
and compile inside the disconnected build VM. The host owns authentication,
authorization, form validation, HTML serialization, and transaction commitment.

Start with [private-notes](../examples/private-notes/src/lib.rs) for text CRUD, or
[task-board](../examples/task-board/src/lib.rs) for integers, choices, optional
values, checkboxes, and custom form layouts.

Use `noxide::prelude::*` for the common declarations and rendering types, or
import individual names as the examples do.

## Resources and capabilities

```rust
#[derive(Resource)]
#[resource(key = "tasks")]
struct Task {
    #[id]
    id: Id<Self>,
    #[field(key = "title", label = "Title", max_bytes = 200)]
    title: String,
    #[field(key = "completed", label = "Completed")]
    completed: bool,
}

#[query(list(Task), allow = owner)]
struct ListTasks;

#[action(create(Task), fields(title, completed), allow = owner, redirect = show_task)]
struct CreateTask;
```

Resource and field keys identify persistent data. Keep those keys when renaming
Rust declarations. Declaration order, Rust module names, labels, and enum display
labels do not change the stored schema. Changing a persistent key requires an
explicit migration.

Supported values are bounded `String`, `bool`, `i64`, unit enums deriving `Choice`,
and one layer of `Option<T>`. Enum variants require stable `#[choice(key = "…",
label = "…")]` declarations. Strings require `max_bytes`; integers may declare
`min` and `max`. Every resource has exactly one `#[id] Id<Self>` field. IDs convey
identity; query and action grants determine permission.

Policies support `owner`, `same_tenant`, `role("writer")`,
`tenant_role("admin")`, and compositions such as
`all(same_tenant, any(owner, tenant_role("moderator")))`. The deployment operator
approves the generated contract. Guest code can reject an operation but cannot
override host policy.

## Pages, components, and routes

```rust
#[page(path = "/")]
fn index(mut tasks: Query<ListTasks>, create: Form<CreateTask>) -> Page {
    let tasks = tasks.fetch();
    Page::new("Tasks", html! {
        main {
            h1 { "Tasks" }
            @if tasks.is_empty() { p { "No tasks yet." } }
            @for task in &tasks {
                article {
                    a href=(routes::show_task(task.id)) { (&task.title) }
                }
            }
            (create)
        }
    })
}
```

The handler signature lists its capabilities. A list query exposes `fetch()`;
a read query exposes `get(Id<Resource>)`. Returned records have ordinary typed
fields. Lists remain bounded and the host supplies pagination links.

A record page uses a path such as `/tasks/{task}` and an `Id<Task>` argument.
Its read operations and mutation forms are bound to that target. Paths have at
most one record parameter. Declare a collection page at `/`; login, logout, and
framework paths are reserved. Ambiguous patterns are rejected at admission.

`routes::show_task(task.id)` and `routes::index()` create checked destinations.
Pass `Fragment` into ordinary Rust layout functions and return a `Page` to set
the document title. `PageResult` supports `NotFound` for missing records.

`html!` supports loops, conditionals, text interpolation, and fragments. Its
finite element set includes `main`, `nav`, `header`, `footer`, `div`, `article`,
`section`, `h1`, `h2`, `p`, `ul`, `li`, `strong`, `em`, `code`, and `pre`.
Links require typed destinations and may contain inline fragments. All string
interpolation becomes text. The host escapes and validates the resulting IR.

The typed fragment builder is also available when a macro is inconvenient.
There are no raw HTML, arbitrary attribute, style, or URL escape hatches.

## Actions and forms

Register declarations once:

```rust
noxide::application! {
    pages: [index, show_task],
    actions: [CreateTask, EditTask => edit_task, DeleteTask],
    forms: [EditTask => task_editor],
}
```

A declared CRUD action has a generated handler. A custom handler receives
`Submission<Action>`, whose immutable input contains exactly the writable field
projection:

```rust
fn edit_task(submission: Submission<EditTask>) -> ActionResult<EditTask> {
    if submission.input().title.trim().is_empty() {
        return Err(EditTask::title.error("Enter a title."));
    }
    submission.apply()
}
```

`apply()` stages the host-retained input and target. It accepts no replacement
record, owner, or target. The host validates the outcome and renders a bounded
response before committing the mutation and receipt. Traps, invalid output,
rejections, and exhausted budgets roll back. Retry protection remains mandatory.

To inspect original values, declare both `inspect = ReadTask` and
`inspect_fields(title)` on an update or delete action. `submission.original()`
then exposes a typed, explicitly authorized projection.

Forms have default controls. Customize them with an ordinary typed function:

```rust
fn task_editor(fields: FormFields<EditTask>) -> FormLayout {
    form! {
        section {
            (fields.title.text_input())
            (fields.completed.checkbox())
        }
        (fields.submit("Save changes"))
    }
}
```

Controls include `text_input()`, `textarea().rows(12)`, `checkbox()`, and
`select()` for declared choices or optional booleans. Their Rust types catch
incompatible controls. Admission independently checks the complete projection,
control compatibility, nesting, and one submit button.

Layout functions run during isolated metadata collection. They describe a static
blueprint: no request data, tokens, or credentials enter the function. The host
fills values and errors and uses the same blueprint after invalid input or a
conflict. Its recovery explanations always remain present. Policy-disabled forms
are omitted; `Form::is_available()` can control surrounding application content.

Text preserves whitespace and normalizes line endings to LF. Nonoptional text
must be nonempty; optional empty text becomes `None`. Missing checkboxes become
`false`, integers use exact decimal canonicalization, and enum keys must match
a declared choice. The host hashes canonical values for receipt matching while
preserving invalid raw values for form recovery. Business rules such as rejecting
whitespace-only notes belong in custom action handlers.

## Isolated checks and builds

The trusted CLI uses the framework's VM runner:

```sh
noxide check --app examples/task-board --name task_board \
  --kernel /path/to/kernel --toolchain /path/to/rust-toolchain \
  --output /tmp/task-check

noxide build --app examples/task-board --name task_board \
  --kernel /path/to/kernel --toolchain /path/to/rust-toolchain \
  --output /tmp/task-build
```

Supply a new output directory. The toolchain needs the
`wasm32-unknown-unknown` target; registry dependencies must already be in the
trusted Cargo cache. `--cargo-home` selects that cache. An installed CLI can use
`--framework /path/to/trusted/noxide-checkout` to locate its builder and approved
dependency catalog.

Application compilation, build scripts, procedural macros, and the native
metadata collector execute only inside the disposable VM. `check` validates the
generated contract; `build` also produces a component admitted under runtime
limits. Neither command approves a deployment automatically. Keep the emitted
`manifest.json` and component together and approve their deployment contract.

Native Cargo commands and editor macro expansion can execute application
dependencies outside this boundary. Use the isolated command's compiler
diagnostics and generated manifest when working with untrusted applications.

## Schema evolution

Build the new application bundle and generate a schema-change draft:

```sh
noxide schema diff old-manifest.json new-manifest.json migrations/002.json
```

Drafts never infer renames. Required backfills, changed field schemas, and
removals contain unresolved placeholders. Edit them deliberately. For example,
adding a checkbox to existing tasks uses:

```json
{
  "op": "add_field",
  "resource": "tasks",
  "field": "completed",
  "value": "false"
}
```

Keep the generated `version`, `from`, and `to` fingerprints. Operations support
resource/field additions, explicit removals, renames, constraint changes,
text/integer conversions, and explicit enum-key mappings. Migration files contain
no SQL or executable callbacks. Commit migration history alongside the source.

Point CONFIG at the new manifest and its approved contract, then rehearse and
apply during maintenance:

```sh
noxide schema check CONFIG migrations/002.json
noxide schema apply CONFIG migrations/002.json
```

`check` runs the complete transition against real data and rolls it back; it
requires the same maintenance access as `apply`. Use a database copy when a
rehearsal must not interrupt serving. Both commands acquire exclusive database
access and reject concurrent request transactions. New requests fail busy while
the lock is held. Migration scans have a 60-second execution deadline; failure rolls back
the entire transition. Stored migration history makes retrying the same committed
migration safe after a lost acknowledgement.

Applying a migration fences old forms and old schemas. Activate the matching
approved bundle afterward. If activation fails, keep the application unavailable
until a compatible bundle is ready. Recovery after a committed destructive
migration requires an explicit forward migration or a verified backup restore.
