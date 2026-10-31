# Effect transport preparation

Status: unregistered P11 transport leaves, awaiting independent review and P10/P11
integration. No endpoint capability, guest network import, worker, outbox or
production service is enabled. This is not complete P11 or transport anonymity
acceptance. No real remote endpoint was contacted in verification.

`Endpoint::checked` validates configuration shape only. It grants no authority.
Future host admission must intersect the named endpoint, deployment approval,
action disclosure and current job/effect/secret grants before constructing a send.
Transport I/O must happen after the database transaction has ended. A canonical
endpoint fixes HTTPS, lowercase ASCII DNS name, explicit nonzero port and exact
ASCII origin path. It rejects IP literals and URL-normalized numeric spellings,
userinfo, query/fragment syntax, percent escapes, dot segments, duplicate slashes,
Unicode and silent hostname normalization. Only POST JSON is implemented.

`TorProxy` accepts only an explicit numeric loopback socket, with no environment
proxy or system resolver. SOCKS5 no-auth negotiation is followed by Tor's remote
RESOLVE command, then a separate numeric CONNECT after address validation. No
application data is sent optimistically before SOCKS success. Unsupported remote
RESOLVE, authentication, malformed replies, domain-name replies and I/O failures
fail closed. The Tor extension returns the resolved IP; it does not grant a new
destination port. Both reply port fields are parsed completely as protocol
metadata. CONNECT uses only the endpoint's declared port. CONNECT BND.PORT is the
proxy's assigned source/bind port, not the destination port.
([Tor SOCKS specification](https://spec.torproject.org/socks-extensions.html),
[RFC 1928, section 6](https://www.rfc-editor.org/rfc/rfc1928.html#section-6))

The IP policy permits ordinary IPv4 global unicast and IPv6 2000::/3 after
excluding all current special-purpose ranges, including mapped, transition,
documentation and special anycast blocks. It deliberately excludes some globally
reachable special-purpose exceptions too. Registry snapshot checked 31 October
2026; refresh it during final integration/security maintenance. Registry flags
and a valid address do not prove actual network reachability.
([IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/),
[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/))

TLS certificate verification and SNI retain the endpoint hostname; HTTP Host
retains that hostname and its declared nondefault port. Numeric CONNECT never
causes a second lookup. Production trusts only the compiled Mozilla root bundle;
there is no configurable insecure verifier or local-CA selector. TLS 1.2/1.3 use
an explicit Ring provider, HTTP/1.1 ALPN, no client certificate, no early data and
no session resumption. Test fixture roots/keys are included only under cfg(test).
Rustls supplies TLS buffering and handshake/record limits in addition to the HTTP
limits below; no response decompression is performed.
([Rustls](https://docs.rs/rustls/0.23.46/rustls/),
[Tokio Rustls flushing](https://docs.rs/tokio-rustls/0.26.6/tokio_rustls/))

Each transport instance has two slots and no wait queue; integration must keep
one shared instance per application. One 10-second deadline covers proxy TCP,
RESOLVE, numeric CONNECT and TLS together. One absolute 30-second deadline covers
the whole send and is clamped to any earlier caller deadline. The future worker
must establish that caller deadline before preflight work, rather than resetting
its budget at transport entry. Request writes, final headers and response discard
all use the same absolute deadline. The implementation spawns no I/O driver.
Canceling its future drops the owned stream and releases its slot. This stops
local I/O; it cannot retract bytes or remote effects already accepted.

Request JSON is validated and capped at 64 KiB. Request headers are capped at
4 KiB and have fixed host-owned names: Host, Content-Type, Accept, Content-Length,
Connection, Idempotency-Key and optional Bearer Authorization. Keys and secret
values have bounded grammars. Secret values are resolved by the future host worker
at send time, never stored in declarations, JSON or guest projections. Endpoint,
body, key and secret Debug values are redacted; errors contain static categories,
not URLs, payloads, headers or underlying secret-bearing diagnostic strings.

Response headers have an 8 KiB cumulative bound, 32 headers per response and at
most two accepted informational responses (100/102/103); upgrades fail closed.
Conflicting/duplicate framing fields and unsupported transfer codings are rejected.
Opaque body/framing consumption is capped at 16 KiB, with a fixed discard buffer,
256 chunk records, 128-byte chunk lines and 16 bounded trailer lines (counts
include their terminators). Chunk extensions are
unsupported, forbidden framing trailers fail closed, and trailers share the body
budget. A close-delimited body exactly at the cap is conservatively limited rather
than reading beyond the cap to distinguish EOF. No body or arbitrary response
header becomes a guest read. This small client intentionally does not implement
every optional HTTP response feature; its bounded supported length rules follow
[HTTP/1.1 framing](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3).

A complete authenticated final status is retained even when opaque discard is
limited, malformed or reaches the deadline. The response reports only numeric
status, bounded numeric Retry-After and Complete/LimitExceeded/Invalid/Deadline.
Known 2xx must be classified delivered by the future worker regardless of discard;
post-header discard cannot independently cause another attempt. Known 4xx are
terminal except 429; eligible 429/5xx follow the future bounded retry policy.
Redirects return a distinct known-status `Error::Redirect(code)` and are terminal;
Location is never used and no redirect is followed. Other errors occur before
validated final headers and remain ambiguous transport errors. External future
cancellation can lose a received result; stable idempotency keys and receiver
deduplication remain necessary. No exactly-once guarantee is made.

Retry-After accepts numeric seconds up to 24 hours; duplicate, invalid or date-form
values are ignored. Future retry logic must clamp this metadata to the remaining
retry window. This leaf neither schedules retries nor inserts/claims/completes
outbox rows. Revocation, grant versions, runtime epochs, restore pausing and
separate enqueue/execution authority remain P10/P11 integration requirements.
P10 must also revisit ordinary DB cancellation/permit ownership: P06's scoped
maintenance proof does not certify a headless executor's termination. Service
bindings must resolve approved core targets without fabricated web credentials,
user-asserted principals or raw-ID grants; a changing fence is not job identity.

The standalone verification script builds only these leaves in a workspace-target
harness, checks its dependency closure against the coordinator's approved lock,
and leaves production registries unchanged. Local SOCKS/TLS fixtures inspect the
exact RESOLVE/CONNECT packets, SNI, Host and secret placement. Other tests exercise
address and endpoint negatives, strict framing, known-status retention, cancellation
at I/O boundaries, two-slot admission and the real 10/30-second deadlines. Local
fixture success does not prove that an operator's proxy is Tor, that a Tor exit
will connect, that a public endpoint accepts the request, or transport anonymity.

Reproduce with `python3 tools/verify_effect_transport.py test` (loopback permission
required), and `python3 tools/verify_effect_transport.py clippy`. Evidence is under
`target/capability-evidence/p11`; build cache is `target/p11-transport`. The custom
harness alone allows dead code because these private leaves are unregistered;
production code has no dead-code suppression that enables a capability.
