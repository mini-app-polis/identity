# identity

The cross-ecosystem identity contract for MiniAppPolis: **principals and grants**,
not just authentication.

One specification with N conformant enforcement points — explicitly **not** a
central auth service on the request path. A central service would put a network
hop and a single point of failure in front of every request in the fleet. This
repo instead defines what a correct enforcement point does, ships a binding that
does it, and provides the fixture suite that proves any other binding agrees.

The design ships here, with the implementation. `ecosystem-standards` holds
rules, not designs, and no service depends on it.

## Scope

| In | Out |
|---|---|
| Principals (human and machine), roles, scopes, explicit grants | Session management, login UI, token minting |
| The four-function binding contract | A runtime service other services call |
| The principal store schema | A shared runtime store |
| The cross-language fixture suite | Per-service business rules |

## The four functions

Every enforcement point implements the same four, in the same order, once per request:

```
verify(credential)          -> VerifiedSubject     raises on failure
resolve(subject)            -> Principal | None    None is a valid answer
authorize(principal, scope) -> Decision            never raises
emit_audit(event)           -> None                never raises into the request
```

Four rather than one, because each step fails differently and each failure needs
a different response. A collapsed `is_allowed(token, scope) -> bool` cannot tell
"your token is forged" from "you are suspended" from "you are exactly who you say
and simply lack this scope" — and cannot record any of them.

`verify` proves who the *issuer* says you are. `resolve` answers what *this
ecosystem* knows about you. Keeping them separate is what stops `sub` being used
as a primary key.

## Principals

Humans and machines are the same shape and resolve through the same decision.
`kind` exists for audit and policy, never as a proxy for privilege — privilege
comes from roles, for both.

A principal's identity is `(issuer, subject)`, and its identifier is a UUID this
store owns. Two Clerk tenants can legitimately mint the same `sub`; multi-issuer
is a design property, not an edge case. The two tenants stay separate: different
products, different audiences.

## Roles and scopes

Roles are named bundles of scopes. Roles are the only thing granted to a
principal; scopes are the only thing checked at an enforcement point.

Scopes are exactly three dot-separated segments — `<domain>.<resource>.<action>`,
e.g. `wcs.notes.read`. Three segments is a deliberate constraint: it keeps scopes
greppable and makes wildcard expansion unnecessary.

Decision precedence is fixed and short:

1. No principal → deny `principal_not_found`
2. Suspended principal → deny `principal_suspended`
3. Scope in any role → allow `granted_by_role`
4. Explicit resource grant → allow `granted_by_explicit_grant`
5. Otherwise → deny `no_matching_scope`

Suspension is checked before roles on purpose. Reversing 2 and 3 would make
suspension advisory.

## The principal store

One schema (`sql/principal-store.sql`), one instance per ecosystem database —
not shared at runtime. The cogs + `api-kaianolevine-com` database gets one;
`deejaytools-com` gets its own. They share the schema, never the rows.

It installs into its own `identity` Postgres schema so it can be added to an
existing database without colliding with application tables.

## Conformance

`schema/` is the neutral source of truth. `fixtures/` is what keeps every
binding honest — the same inputs, the same expected decisions, in every
language. `authorize` is the part that can be pinned exactly, because it is the
only one of the four that is pure: no network, no database, no sink.

A binding is conformant when it passes the fixture suite. Nothing else counts.

## Status

Early. The Python binding and the `authorize` fixture suite are real; `verify`
and `resolve` reference implementations, the TypeScript binding, and the
`verify`/`resolve`/`audit` fixture directories are not filled in yet.
