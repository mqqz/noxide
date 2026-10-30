# Application API

Noxide applications declare resources and permissions in Rust, render Document IR,
and compile locally for trusted code or in an optional disconnected build VM. The host owns authentication,
authorization, form validation, HTML serialization, and transaction commitment.

Start with [private-notes](../examples/private-notes/src/lib.rs) for text CRUD, or
[task-board](../examples/task-board/src/lib.rs) for integers, choices, optional
values, checkboxes, and custom form layouts. The [forum](../examples/forum/README.md)
exercises typed references, public and anonymous posting, and moderation.

Use `noxide::prelude::*` for the common declarations and rendering types, or
import individual names as the examples do.

## Start with one application module

Create a project with the trusted CLI:

```sh
noxide new my-notes
```

The destination must be new and its parent must exist. The command writes a
standalone notes application and a README with check/build commands.
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

CRUD entries name each enabled mutation. A resource may have multiple named
creates, updates, and deletes, in one block or across blocks. Names must be unique
across the module, including explicit actions. Each action retains its own policy,
fields, redirect, hooks, layout, and `Form<Action>` route binding. Create and update
require separate `fields(...)` lists. Every entry requires `redirect(page_name)`
or the typed reference destination `redirect(reference(field, page_name))`. Omitted
operations generate nothing. Existing host rules require create to name every writable
ordinary stored field (references are host-bound) and ordinary create/update
redirects to target a record page. Adding a writable field
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

Supported values are bounded `String`, `bool`, `i64`, references using `Id<T>`, unit enums deriving `Choice`,
and one layer of `Option<T>`. Enum variants require stable `#[choice(key = "…",
label = "…")]` declarations. Strings require `max_bytes`; integers may declare
`min` and `max`. Every resource has exactly one `#[id] Id<Self>` field. IDs convey
identity; query and action grants determine permission.

Policies support `owner`, `same_tenant`, `role("writer")`,
`tenant_role("admin")`, and compositions such as
`all(same_tenant, any(owner, tenant_role("moderator")))`. The deployment operator
approves the generated contract. Guest code can reject an operation but cannot
override host policy.

Operators manage assignments with `noxide role grant|revoke CONFIG.json ACCOUNT_ID ROLE
--global` or `--tenant TENANT`, and inspect them with `noxide role list CONFIG.json
ACCOUNT_ID`. Global `role` and scoped `tenant_role` predicates are distinct; a tenant
grant must match the account's existing nonempty tenant. Grants require that exact
role and scope in the configured approved manifest. Registration grants no roles.

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

Layout functions run during metadata collection. They describe a static
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

The CLI builds trusted applications locally by default:

```sh
noxide check --app examples/task-board --name task_board \
  --output /tmp/task-check

noxide build --app examples/task-board --name task_board \
  --output /tmp/task-build
```

Supply a new output directory. The toolchain needs the
`wasm32-unknown-unknown` target; registry dependencies must already be in the
trusted Cargo cache. `--cargo-home` selects that cache. An installed CLI can use
`--framework /path/to/trusted/noxide-checkout` to locate its builder and approved
dependency catalog.

Application compilation, build scripts, procedural macros, and the native
metadata collector execute on the host with your user permissions by default.
For untrusted apps or dependencies, add `--isolated --kernel /path/to/kernel
--toolchain /path/to/rust-toolchain`; these operations then run in a disposable VM. `check` validates the
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
// Article.published declares #[field(initial = false)].
#[action(create(Article), allow = public, fields(title, body), redirect = article)]
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

## Parent relationships and scoped pagination

The [declarative query design](architecture/queries.md) describes selection,
ordering, parameters and previews, with compatibility and execution constraints.

A resource may declare one required, immutable reference using `Id<T>`. A plain
reference has no visibility relationship to its target:

```rust
product: Id<Product>,
```

The forum adds a gate to its reference:

```rust
#[field(visible(published = true), create_when(locked = false))]
thread: Id<Thread>,

#[action(create(Reply), fields(body),
         bind(thread = target, eligible = PublicThread),
         allow = owner, redirect = show_reply)]
struct CreateReply;
```

These are declaration fragments; declare the resources and eligible query first.
Every reference create explicitly declares `bind(...)`. The eligible query must
be a read of the target on every page carrying the form. At submission the host
checks the signed target identity, revision and incarnation, source create policy,
the eligible read's complete authorization and visibility, and both gate predicates
inside the write transaction. Eligibility is not rechecked after creation.

A gate's `visible` condition hides public source reads and lists; `create_when`
additionally blocks new records. Private operations retain their declared policy.
Locking a thread leaves existing reply reads, edits and deletion unaffected.
Missing targets hide public gated records. A gate target cannot itself have a gate.

References have no initial value, are absent from forms and action writable fields,
and cannot appear in filters or disclosures. Attempts to submit or update one fail.
A list can declare `scope(thread)` to select the page's thread. Lists of gated
resources receive this scope automatically in SDK lowering; host admission requires
it explicitly in the manifest. Ungated references also support unscoped collection
lists, so an order list survives loss of access to a product.

Deleting a target with any referencing record is rejected, including records the
caller cannot see. Whoever may create a referencing record can thereby block the
target's deletion. Creation and deletion share transactional integrity checks;
migrations reject orphaning, adding references to existing resources and changing
their target. The host manages reference indexes on both backends.

Follow is a separate read grant:

```rust
#[query(list(Order), allow = owner, page_size = 20)]
struct MyOrders;
#[query(read(Product), allow = public, visible(available = true),
        fields(name, price), via(MyOrders.product))]
struct OrderProduct;

let orders = my_orders.fetch();
let products = order_product.follow_many(&orders)?;
```

The source must return the reference field. The follow must share a route with
its source and accepts only that query's output type. The host resolves references
from provenance for records actually returned during this request, independently
of guest copies. It checks target policy, visibility, gates and projection on every
follow. Reading an order alone reveals only its projected product ID.

A follow runs once per request with at most 20 inputs. Batched distinct target reads
preserve input order and duplicates; missing and denied targets both produce `None`.
The complete positional vector is returned or the request fails within existing
call, deadline and shared list-result byte budgets. Follow results cannot be followed
again. See the [reference model](architecture/references.md) and
[shop fixture](../tools/fixtures/sdk/shop.rs).

The [forum example](../examples/forum/README.md) exercises public threads,
account-owned and edit-secret replies, editing, thread locks, and moderation.


A non-optional boolean field may declare `#[field(initial = false)]` (or
`true`). Only boolean literals are supported by the macro; choice variant
syntax is a follow-up. The host validates manifest initial values independently,
including canonical boolean or declared choice values and storage limits.

Initial fields must be omitted from every create action's `fields(...)`.
They are absent from typed create inputs and forms; submitted keys are rejected.
The trusted host inserts the approved value at create commit, including custom
handler creates. Creates must retain at least one writable field.

This is a creation-time guarantee only. Update actions may list these fields,
and their policies determine who can change them. An owner update listing
`published` allows owners to publish themselves. Initial values affect the
application contract digest and invalidate old submission tokens, but do not
affect the schema digest. They apply to new rows; migration `AddField.value`
remains a separate operator-selected backfill for existing rows.

Contract review follow-up: the CLI currently prints approval and schema hashes, without a human-readable policy summary. A future summary should list each initial field and value together with every update action that can write it and that action’s policy. Until then, inspect the full approved manifest.

### Redirecting through a reference

A mutation can declare its reference target page as the destination:

```rust
create PostReply { fields(body), bind(thread = target, eligible = PublicThread), redirect(reference(thread, thread)) }
```

The same destination syntax works for update and delete. The named page must
address the reference target resource and provide its applicable read
operation. The host captures the immutable target identity, including its
incarnation, from the validated relationship. Submitted identifiers and guest
URLs cannot select the destination.

The host commits the mutation and its recovery receipt before resolving reference
navigation. It applies the destination's normal resource read authorization to
the current principal without executing the destination page handler. A source's
edit secret does not confer access to a private target. Missing, replaced, or
unreadable targets, navigation timeouts, and post-commit lookup failures produce
a generic mutation-success response. They do not undo the mutation or invite a
new submission. Link presence can reveal whether navigation is currently allowed;
the fallback does not identify the target or explain why access is unavailable.

Anonymous creation first displays the original edit secret, with an optional
“Continue to thread” link. Save the secret before continuing. The host never
automatically redirects past this handover. If delivery is interrupted, retain
the original form's recovery information and replay that submission to recover
the same receipt and secret; replay does not create another record or generate
a replacement secret. Each replay evaluates target visibility again, including
after the child has been deleted.

The [architecture layers](architecture/layers.md) describe explicit SDK declarations,
optional convenience lowering, and independent host enforcement.

## Account references and principal policies

The [declarative query design](architecture/queries.md#two-existing-execution-paths)
records how query extensions preserve account-list execution and authorization.

`AccountId` is an opaque identity, distinct from a login name. Parsing checks its
canonical encoding only; it does not grant authority or prove account eligibility.
Declare references explicitly:

```rust,ignore
#[derive(noxide::Resource)]
#[resource(key = "messages")]
struct Message {
    #[id] id: noxide::Id<Self>,
    #[field(scope = same_tenant)] recipient: noxide::AccountId,
    #[field(max_bytes = 4096)] body: String,
}
#[noxide::query(list(Message), allow = any(owner, principal_is(recipient)), page_size = 20)]
struct ListMessages;
#[noxide::query(read(Message), allow = any(owner, principal_is(recipient)))]
struct ReadMessage;
```

The host validates references atomically at record creation: creator and targets
must be active and share a nonempty tenant. Only operator-assigned tenants are
supported. Self-registered accounts have no tenant and cannot participate in
these bindings. Empty tenant never means a shared default tenant.

Account fields are required, have no defaults, and are limited to four per
resource. They cannot appear in update projections. Schema conversion and
backfilling an existing resource with account references are unsupported; create
a new resource instead. Same-kind constraint changes, such as tightening
`max_bytes`, are allowed when stored IDs remain valid and the binding scope is
unchanged. Identity and immutability are separate concepts: the
initial write contract enforces immutability.

`principal_is(field)` is available only on read/list operations, including inside
`any`/`all`. It compares the stored identity with the authenticated principal;
it adds no tenant check. For recipient access confined to the record's tenant,
use `any(owner, all(principal_is(recipient), same_tenant))`. Owner remains the
host-controlled creator. Recipient read access never implies mutation authority.

Signed-in users can view their own ID at the host's `/account` page (configurable
as `presentation.account_path`). They share IDs themselves. There is no guest
directory or login-name resolution capability; the inbox displays opaque IDs.
An exact ID can be tested for current binding eligibility through creation
success. Ineligible targets receive the same public rejection, but database
lookups are not claimed to be timing-indistinguishable.

The inbox uses ordered owner and recipient index scans merged before pagination.
It returns full pages when enough authorized records fit the output budget.
Policies requiring residual filtering use bounded candidate scans and may return
short or empty pages with a continuation. Continue using the host-rendered
pagination links, rather than treating a short page as exhaustion.

## List selection and disclosure

Lists accept up to four distinct equality filters on Boolean or Choice fields:

```rust
#[query(list(Item), allow = public, visible(listed = true),
        filter(status = Status::Available), disclose(status),
        order = created_desc, page_size = 12, fields(title, price))]
struct AvailableItems;

#[query(list(Message), allow = any(owner, principal_is(recipient)),
        filter(archived = false), order = created_desc, page_size = 20)]
struct InboxMessages;
```

These are declaration sketches; declare the resources and choices first. Values
must encode canonically for the declared field. Account, reference, text and integer
fields are ineligible, and a filter cannot repeat the public visibility field.
`filter` is list-only. It selects among accessible records and never grants access:
a sold item disappears from the available list but remains readable through an
approved read. Visibility governs both public lists and reads instead.

For public queries, every filtered field outside `fields(...)` must appear in
`disclose(...)`, and every disclosure must name such a field. A literal filter
reveals whether the field equals that value for each visible record. Disclosure
approves that inference only; it does not add the field to returned records.
Private lists need no disclosure: their policy already permits complete records.
Both execution paths bind literal values in SQL and check selection again on
stored rows. Residual policies retain bounded scans and possible short/empty
pages with continuation. See the [query design](architecture/queries.md) for the
parameter disclosure rules and index lifecycle.

## Required route parameters

Declare URL parameters on the page and bind them in list filters:

```rust
#[query(list(Item), allow = public, visible(listed = true),
        filter(category = param(category)), disclose(category), fields(title))]
struct CategoryItems;

#[page(path = "/items", params(category), access = public)]
fn items(mut available: Query<CategoryItems>) -> Page {
    let category = available.param("category").expect("bound category").to_owned();
    Page::new("Items", html! { main {
        h1 { (&category) }
        @for item in available.fetch() { p { (&item.title) } }
    } })
}
```

Parameters are explicitly declared and required, with at most four per route.
The index route `/` must remain unparameterized for host-owned login, home
navigation and recovery links. Put required list parameters on a separate route.
Every declaration must be used and every query parameter must be declared on
each route that uses it. Uses must agree on Boolean or Choice kind, including
identical choice variants. They cannot carry account IDs. `Query::param(name)`
returns the host's canonical read-only value; `fetch()` still takes no arguments.

Generated helpers accept Boolean or Choice values, for example
`routes::items(Category::Books)`, and build canonical parameters. Record targets
retain their existing checks and precede parameters in the helper arguments.
The host validates both target and exact parameter set, including links in
Document IR. Next-page URLs retain sorted canonical parameters before `cursor`.
A cursor for books cannot be used for games or another authenticated account.

Choose an unparameterized destination for create, update and delete redirects,
including `redirect(reference(field, page))`. Redirect declarations do not bind required
query parameters; admission rejects destinations that declare them.

The form-urlencoded query string is limited to 1,024 bytes. Missing, unknown,
duplicate, malformed or noncanonical parameters return the same 404 response as
an unknown route before database or session lookup. These rejections still consume
the circuit budget and require request admission; exhausted capacity returns the
standard busy response. Valid values without matches render a normal empty list.
Parameter values are never logged by the host. A public parameter filter on an unprojected Boolean or Choice field effectively
reveals that field: callers can try each value. `disclose` approves that inference
without projecting the field. The [public articles example](../examples/public-articles/src/lib.rs)
includes a category route with these host checks.

## Bounded previews and several lists

A page may declare at most four list operations, with at most one paginated list
and a combined declared page size of at most 40. Mark the other lists as previews:

```rust
#[query(list(Item), allow = public, visible(listed = true),
        filter(category = param(category)), disclose(category), fields(title),
        page_size = 3, preview(see_all = items))]
struct CategoryPreview;
```

`preview` alone omits a full-list destination. Fetch once with
`let sample = query.fetch_preview()`: `sample.items` contains a strict prefix and
`sample.truncated` says more may exist. Show an explicit incomplete state when
truncated, including an empty residual-policy preview. `fetch()` remains the
paginated API; reuse its returned values instead of invoking an operation again.
The host permits every route operation, including reads, at most once per request.

Previews ignore the paginated cursor and never generate next-page links. A page
with only previews also ignores `cursor` after strict query-string validation.
Truncation is true on row or byte limits, a positive look-ahead, or a bounded
residual scan. The host renders a checked “See all” link only when truncated and
`see_all` names a route with an equivalent full list: same resource, policy,
visibility, scope and selection, with declared parameters drawn from the preview page.
Parameter kinds must match across both routes, including Choice variants. The
destination must accept every canonical source value, including empty values
allowed by optional resource fields. The link retains canonical values and
existing record-target checks.

All list results share a 131,072-byte serialized budget; each result retains the
65,536-byte limit. The host reserves room for a pending paginated result and
preview envelopes, so preview invocation order cannot consume pagination's entire
allowance. Pages also retain the 16-invocation request cap and deadline; list scans,
record loads and catalog lookups share an additional 4,096-call work budget.
Aggregate limits supplement per-list limits and the residual candidate bound.
Document IR still has its own 65,536-byte limit. Render summaries or selected fields
when large records across several lists would exceed that limit; fetching bounded
results does not grant a larger document budget.

The [public articles example](../examples/public-articles/src/lib.rs) includes an
`/overview` page combining pagination and a category preview, and `/highlights`
with a preview alone. Neither requires guest-built queries or host prefetch.
