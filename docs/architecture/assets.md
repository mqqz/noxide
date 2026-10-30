# Public package assets and rich documents

P05 implementation slice: independent leaf admission and executor transport. The
shared manifest, SDK lowering, HTTP dispatch and full application browser wiring
remain integration gates. These modules do not enable an asset capability alone.

An asset declaration names a canonical relative package entry, its lowercase
SHA-256 source digest and one of PNG, JPEG, WebP, WOFF2 or CSS. The complete bundle
must match the declarations exactly. Admission rejects duplicate names/digests,
absolute paths, traversal, hidden components, malformed UTF-8, and noncanonical
names. Limits are 128 files, 4 MiB/file and 16 MiB total, including compiled CSS.
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
at most ten seconds and iteration count at most ten. Font faces have a literal
family, exactly one declared WOFF2 URL and optional enumerated style/weight/display.

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

The exporter does not dereference archive symlinks and caps the stream with head.
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
