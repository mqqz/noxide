# Application API

Noxide applications declare resources and permissions in Rust, render Document IR,
and compile inside the disconnected build VM. The host owns authentication,
authorization, form validation, HTML serialization, and transaction commitment.

Start with [private-notes](../examples/private-notes/src/lib.rs) for text CRUD, or
[task-board](../examples/task-board/src/lib.rs) for integers, choices, optional
values, checkboxes, and custom form layouts.

Use `noxide::prelude::*` for the common declarations and rendering types, or
import individual names as the examples do.

## Start with one application module

Create a project with the trusted CLI:

```sh
noxide new my-notes
```

The destination must be new and its parent must exist. The command writes a
standalone notes application and a README with isolated check/build commands.
It does not run Cargo, fetch dependencies, or approve deployment. Existing files
are never overwritten. Package names use lowercase ASCII letters, digits,
underscores, or hyphens and start with a letter.

Use an inline module at crate root. The macro registers immediate pages, explicit
actions, CRUD declarations, and the resources they use. Unused resource types add
no schema or operations. It emits the existing application entry point and
contract collector.

```rust
#[noxide::app]
mod notes {
    use noxide::prelude::*;

    #[derive(Resource)]
    #[resource(key = "notes", owner)]
    struct Note {
        #[id]
        id: Id<Self>,
        #[field(max_bytes = 4096)]
        body: String,
    }

    #[page("/")]
    fn index(mut notes: List<Note>, create: Form<CreateNote>) -> Page {
        Page::new("Notes", html! {
            main {
                h1 { "My notes" }
                @for note in notes.fetch() { p { (&note.body) } }
                (create)
            }
        })
    }

    #[page("/notes/{note}")]
    fn show(note: Id<Note>, mut read: Read<Note>) -> PageResult {
        let note = read.get(note).ok_or(NotFound)?;
        Ok(Page::new("Note", html! { main { p { (&note.body) } } }))
    }

    crud! { Note {
        create CreateNote { fields(body), redirect(show) }
    } }
}
```

`List<Resource>` and `Read<Resource>` are app-macro shorthand for distinct typed
queries. They expose the existing `fetch()` and `get(id)` methods. They require
a directly named resource in this module with an explicit `owner` annotation.
The host binds owner policy to the authenticated user. `owner` is a default for
shorthand, so explicit queries may still declare other approved policies.
An unmarked resource receives no inferred access policy.

CRUD entries name each enabled mutation. Create and update require separate
`fields(...)` lists, and every entry requires `redirect(page_name)`. Omitted
operations generate nothing. Existing host rules require create to name every
stored field and create/update redirects to target a record page. Adding a field
therefore requires updating create explicitly before admission succeeds. An optional `allow = ...` forwards to the existing
policy parser; otherwise the resource must be marked `owner`. For example:

```rust
crud! { Note {
    create CreateNote { fields(body), redirect(show_note), handler(create_note) }
    update EditNote { fields(body), redirect(show_note), handler(edit_note), layout(note_editor) }
    delete DeleteNote { redirect(index) }
} }
```

Hooks use the existing `Submission<Action>` and `FormFields<Action>` signatures.
For an explicit `#[action(...)] struct EditNote;`, associate hooks with:

```rust
hooks! {
    EditNote { handler(edit_note), layout(note_editor) }
}
```

Each hook must name an immediate, unconditional function in the app module; that
function may call helpers imported from elsewhere. Do not repeat a hook
association already supplied in a CRUD entry. Merely registering an action does
not bind it to every page: the page must receive `Form<Action>` and the host
continues checking route, target, fields, CSRF, and submission scope.

Use `Query<ExplicitQuery>` for public projections, tenant/role policies, imported
resources, and other advanced cases. The [public-articles example](../examples/public-articles/src/lib.rs)
shows anonymous list and record pages that cannot read unpublished rows or private
fields. The resource's owner default does not override those explicit policies.

Resource keys remain explicit. Field keys default to their Rust names and labels
to human-readable names; explicit `key` and `label` options override these defaults.
Text still requires `max_bytes`. Renaming an inferred field key is a schema
change: review the contract diff and use the existing explicit schema workflow.
Use explicit field keys when Rust names should be independently refactorable.

The macro accepts inline modules only and does not discover nested modules,
imported declarations, or declarations produced by other macros. It rejects
conditional contract declarations and hooks. Ordinary helper code may use
conditional compilation. Declare exactly one app module at crate root.
Generated query names (`__Noxide_list_Note`, `__Noxide_read_Note`) are reserved
implementation names. Adding routes or operations still requires operator
approval; moving declarations to another Rust namespace changes operation IDs.

The [lowering contract](sdk-lowering.md) describes the explicit equivalents and
verification. The remaining sections document the explicit SDK, which remains
available when application structure or policies need more control.

## Security requirements for application APIs

The [security contract](architecture/runtime.md#security-contract) governs all
application APIs. Declarations request narrowly scoped capabilities; the host
approves and checks them. Guests cannot override identity or grants, access host
secrets, or obtain ambient filesystem, network, or process access. Use typed
queries/actions and Document IR so authentication, authorization, escaping,
headers, and CSRF stay under host control.

Keep inputs, stored fields, query results, and documents bounded. Do not depend on
external requests, third-party browser resources, or sensitive logging: these are
unavailable by default. Adding a capability must preserve host checks and budgets.

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

## Public pages

Public queries require a host-enforced visibility predicate and field projection:

```rust
#[derive(Resource)]
#[resource(key = "articles")]
pub struct Article {
    #[id]
    pub id: Id<Self>,
    #[field(key = "title", max_bytes = 256)]
    pub title: String,
    #[field(key = "body", max_bytes = 4096)]
    pub body: String,
    #[field(key = "published")]
    pub published: bool,
}

#[query(list(Article), allow = public, visible(published = true), fields(title, body))]
pub struct PublishedArticles;

#[page(path = "/", access = public)]
fn index(mut articles: Query<PublishedArticles>) -> Page {
    Page::new("Articles", html! {
        main {
            h1 { "Articles" }
            @for article in articles.fetch() {
                article {
                    h2 { (&article.title) }
                    p { (&article.body) }
                }
            }
        }
    })
}

noxide::application! {
    pages: [index],
    actions: [],
    forms: [],
}
```

The host filters rows in SQL, validates their complete stored fields, and returns
only `title` and `body`. The SDK generates `PublishedArticlesRecord`, which has
those typed fields and an `id()` method returning `Id<Article>`. Private queries
continue returning the complete resource type. A public `read(Article)` query
uses the same declaration options and returns `None` for missing or unpublished
records.

Manifest admission enforces these rules:

- `public` must be the entire operation policy, serialized as `any: [["public"]]`.
  It cannot occur inside `any(...)` or `all(...)` in macro declarations.
- Only `List` and `Read` operations may be public. Both `visible(...)` and a
  nonempty `fields(...)` projection are required. Projected names must be unique
  fields of the resource.
- Visibility names a boolean or choice field and an already canonical value.
  Boolean declarations emit `true` or `false`; a choice expression such as
  `visible(status = Status::Published)` emits that variant's declared key.
- Non-public operations cannot specify visibility or a read projection. An
  action's `inspect` cannot reference a public operation.
- A route with `access = public` contains only public operations and no forms.
  Public operations may also appear on authenticated or optional public routes.
- `access = public_optional` permits public or private operations and forms.
  Anonymous visitors receive no forms; signed-in visitors retain the usual
  host-authorized forms. Omitting `access` keeps a route authenticated.

A public route ignores session cookies. An optional public route treats missing,
invalid, expired, or revoked sessions as anonymous, but returns 503 when session
verification is unavailable. Anonymous page rendering cannot invoke owner,
tenant, or role authority. All responses retain `Cache-Control: no-store`.

## Actions and forms

With the explicit SDK, register declarations once:

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

## Anonymous submissions and edit secrets

A public create action accepts anonymous submissions. Capability actions require
an edit secret for the exact record:

```rust
#[action(create(Article), allow = public, fields(title, body, published), redirect = article)]
struct PublishArticle;

#[action(update(Article), allow = capability, fields(title, body), redirect = article)]
struct EditArticle;

#[action(delete(Article), allow = capability, redirect = index)]
struct DeleteArticle;
```

Use `access = public_optional` on pages that offer these forms. Public read
operations still require visibility and field projection; public create
operations forbid both. `capability` must stand alone and is valid only for
update and delete. The host adds a password input for the edit secret. Capability
forms start with blank values, so their fields cannot disclose values outside a
public read projection. A capability never grants an owner, role, tenant, or
inspection policy to application code.

The host issues or reuses a 900-second anonymous cookie (`noxide_anon` by default)
and binds form tokens and CSRF to that browser. Cookies and edit secrets never enter `RequestView`.
Every anonymous mutation uses the receipt protocol and bounded anonymous-write
admission. Responses retain `Cache-Control: no-store`.

After a public create commits, a fixed host page shows the edit secret and a
record link. Save the secret before leaving that page. Retrying the same form
recovers the same secret while it remains current. The host stores only record,
capability-version and key identifiers in the receipt outcome. It ignores the
application's create redirect when displaying this handover.

`GET /_noxide/capability/{resource}/{id}` offers a host-owned rotation form by
default. Operators can change its prefix, cookie name and host field names in the
[deployment presentation settings](running-applications.md#deployment-presentation).
Submitting the current secret replaces it. Retrying that rotation recovers the
same replacement; retrying an earlier create or rotation after its version has
been replaced displays a revoked message. Deleting the record also revokes its
secret. A secret belongs in the password input, never a link or URL. Edit secrets bind
to persistent resource identity, so an approved resource rename or bundle-ID
change preserves access.
