# Public package assets and rich documents

Protocol v7 implements asset admission, SDK lowering, the executor transport and
host HTTP/rendering integration. Application construction requires an independently
admitted bundle matching the approved manifest. This is tested implementation,
not an audited security or transport-anonymity claim.

An asset declaration names a canonical relative package entry, its lowercase
SHA-256 source digest and one of PNG, JPEG, WebP, WOFF2 or CSS. The complete bundle
must match the declarations exactly. Admission rejects duplicate names/digests,
absolute paths, traversal, hidden components, malformed UTF-8, and noncanonical
names. `MAX_ASSET_NAME_BYTES` is 96 bytes for the complete relative logical
name, including slashes. This one bound applies to protocol declarations, pack
entries, source snapshots, image references and stylesheet references. With tar's
`./` prefix and a directory slash it fits USTAR's 100-byte name field; PAX and
long-name extension records remain forbidden. Limits are 128 files, 4 MiB/file
and 16 MiB total, including compiled CSS.
Assets are public: do not package secrets or private attachments.

The host retains immutable admitted bytes. Images and fonts are addressed by
their exact byte digest. CSS is compiled into scoped canonical bytes and receives
a separate serving digest; its declaration retains the source digest. HTTP must
serve the digest of the delivered bytes, typed MIME, `nosniff`, `no-store`, and
restrictive same-origin CSP. Asset lookup accepts only the exact canonical path,
with no query/fragment aliases. Serving grants no guest network authority.

PNG/JPEG/WebP admission uses [`image` 0.25.9 metadata readers](https://docs.rs/image/0.25.9/image/struct.ImageReader.html) with a 4 MiB encoded
bound, 8 MiB metadata allocation limit and checked nonzero width × height at most
16 million pixels. It does not decode pixels or certify complete pixel-stream
validity. WOFF2 admission checks fixed-header length, flavor, table count,
reserved field, compressed/expanded size and metadata/private offsets. It does
not decompress or certify the font tables. Browser decoding remains a separate
boundary. Malformed/truncated metadata fails closed.

## Static CSS grammar, version 1

[Servo `cssparser` 0.38.0](https://docs.rs/cssparser/0.38.0/cssparser/) supplies every lexical token and nested-block parse.
Admission rejects malformed strings/comments, implicit EOF block closure,
unknown tokens, rules, properties and value forms. Source is at most 64 KiB,
16,384 tokens, 512 rules including keyframe blocks, and eight nested blocks.
Each rule has at most 128 declarations and each value at most 126 tokens;
selectors have at most 32 comma groups and 256 tokens/group. Compiled output is
at most 256 KiB and remains within the total bundle limit.

Selectors consist of ASCII type/universal selectors, class selectors, descendant
and `>`, `+`, `~` combinators, and these nonfunctional pseudo classes: hover, focus,
focus-visible, focus-within, active, first-child, last-child, only-child, empty,
checked, disabled, enabled and open. Every selector group is prefixed with
`.noxide-app ` after parsing. Each selected element therefore remains a descendant
of that root, including sibling-combinator results. The host owns the root marker;
application class tokens cannot create it. No ID selectors, attribute selectors,
pseudo elements, selector functions, nesting selectors or namespaces are admitted.

The property grammar in `assets/css.rs::property` enumerates literal layout,
spacing, sizing, grid tracks, flex layout, border, color, typography, text,
container and animation forms. Unsupported shorthand forms fail closed.
Lengths use px/em/rem/ch/ex/vw/vh/vmin/vmax, bounded to 10,000 units; percentage
bounds are 10,000%. Negative values are limited to explicitly allowed spacing.
Colors use enumerated names, 3/4/6/8 hex digits or comma-form rgb/rgba/hsl/hsla
with checked component/alpha ranges. Functions such as calc/min/max/clamp,
transforms, gradients, custom properties, inheritance keywords and `!important`
are outside this version's grammar.

Allowed at-rules are `@media`, `@container`, `@keyframes` and `@font-face`.
Media/container queries are parenthesized min/max width/height literal lengths
joined by `and`; container queries may name one ASCII container. Keyframes use
`nxa-` names, from/to/0–100% selectors, at most 32 blocks, finite duration/delay
at most ten seconds and iteration count at most ten. Font faces have a literal `nxa-` family (preventing global replacement of host
control fonts), exactly one declared WOFF2 URL and optional enumerated style/weight/display.

Only `background-image: url(...)` and font-face `src: url(...)` can load resources.
URLs must exactly equal an already-declared digest asset path of the corresponding
image/font MIME. Imports, external/data/protocol-relative URLs, URL query/fragment
aliases, attr/var/local, image-set, resource indirection and all unknown functions
are rejected. No application stylesheet is included on host login, registration,
account, capability-credential or credential-recovery pages. On application pages,
only guest document content belongs inside the `.noxide-app` root; host account
navigation and controls remain outside it.

## Rich document leaf

`document::PresentationNode` represents text, declared images with required alt
text, resolved route links, labeled navigation and typed elements. Class tokens
have at most eight unique ASCII names of at most 64 bytes and cannot use the host
root marker. The host validates table section/row/cell structure, requires a first
summary for details, rejects orphan structural nodes and HTML parser reparenting,
and escapes every text/attribute value. There is no raw HTML, script, inline style,
DOM ID, arbitrary browser URL or guest header operation. Rich subtrees consume the
same document node, depth and final output budgets as ordinary instructions.

## Executor export boundary

`public/` belongs to the snapshotted application. A trusted executor recipe emits
an uncompressed USTAR archive after compilation/metadata collection. For hostile
inputs this recipe runs only in the disconnected disposable build VM. The local
backend remains an explicit trust decision for trusted code/dependencies.

The exporter does not dereference archive symlinks. It creates one private
mode-0600 FIFO outside the public tree, starts a bounded head consumer, runs tar
in the foreground and retains both exit statuses. It waits for its consumer and
removes only the known FIFO path. Only successful tar and head statuses permit
an asset envelope; base64 failure also marks export failed. A tar exit 2 or
SIGPIPE never promotes a partial archive. Head retains the existing archive cap;
local process-group/VM deadlines and cleanup cover blocked work and cancellation.
The host validates raw USTAR framing before parsing members, including entry
types, octal sizes, extensions and trailing data. It never extracts paths.
Symlinks, hardlinks, devices, sparse entries, duplicate names, traversal and all
extension records fail. Valid entries become a canonical `assets.pack` binary
transport with per-entry bounds; host admission independently rechecks the pack,
manifest match, bytes, digests, MIME and CSS.

The existing diagnostic console limit remains 16 MiB. A single syntactically
validated ASSETS base64 envelope has its own 24,393,320-byte ceiling, including
worst-case CRLF wrapping. The decoded archive cap is 17 MiB (16 MiB data plus
1 MiB bounded tar overhead). Combined console memory is at most 41,170,536 bytes.
Malformed/duplicate/incomplete envelopes fail, and deadlines/process cleanup still
apply. This boundary is transport validation, not deployment or audited anonymity
proof. The complete integrated SHA still requires hostile-VM and NoJS all-network
attempt browser evidence.

## SDK and lifecycle

Place only public declared files under the application's `public/` directory.
Declare markers inside `#[noxide::app]`:

```rust,ignore
#[asset("site.css", Css)]
pub struct Theme;
#[asset("tile.png", Png)]
pub struct Tile;
// In a page: html! { (stylesheet::<Theme>()) main { (image::<Tile>("Tile")) } }
```

The attribute hashes bounded files during compilation inside the selected build
executor and emits only logical name, MIME and digest metadata; asset bytes never
enter guest Wasm. `#[app]` registers the markers. The explicit equivalent implements
`AssetType`, the relevant `ImageAsset`/`StylesheetAsset` marker, and registers its
`AssetDeclaration` with `ApplicationDefinition::asset` or
`application! { assets: [Theme, Tile], pages: [...] }`. `AssetRef` admits logical
names, never host paths or user URLs. Rich helpers lower to the canonical
`Instruction::Rich`; stylesheets lower to `Instruction::Stylesheet`.

Build validates assets.pack independently; activation and startup re-admit it.
`Config.assets` is the operator's pack path; omission grants only an empty bundle
and fails when any asset is declared. Asset changes require contract approval.
Wire v7 requires a rebuild/reapproval of old contracts; receipt3 and storage11
remain unchanged. No database deletion or compatibility executor is required.

Digest-only GET responses clone immutable Arc-owned bytes with a maximum of eight
outstanding asset bodies and no asset queue. Permits live until those bytes drop;
the existing60-second connection deadline bounds delivery. Nonempty/chunked GET
bodies are rejected with connection close. No per-request4MiB file copy, filesystem
IO, database lookup, user cache validator or ambient network authority is involved.
The CSS root is emitted only when an application stylesheet is linked, preserving
unstyled output and host credential-page privacy. Operator CSS policy is separate.

The working public-articles `/assets_demo` and authenticated `/assets_preview`
pages use original CC0 PNG/WOFF2/CSS fixtures with reproduction/provenance alongside
the example. Its native test compares the complete convenience manifest with
explicit registration and compares typed helpers with exact canonical IR.
`tools/test_packaged_assets.py` exercises a real packaged component in Firefox
with JavaScript disabled and a strict recording proxy, including login/register/
account exclusion, host toolbar isolation, native details/table/nav, startup
forgeries and byte immutability after pack-file tampering. Handover/recovery
exclusion is also covered directly through the host's credential renderers.
