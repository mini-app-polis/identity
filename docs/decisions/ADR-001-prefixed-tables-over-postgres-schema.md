# ADR-001: Prefixed Tables Over a Postgres Schema

**Date:** 2026-09-02
**Status:** Accepted
**Repo:** identity

---

## Context

The principal store needs a namespace. Its seven tables — issuers, roles,
role scopes, principals, principal roles, explicit grants, audit events —
carry generic names that would collide with application tables in any
database they land in. `roles` and `principals` in particular are names an
application is entitled to want for itself.

Postgres offers the obvious tool: put them in a schema, `identity.roles`,
`identity.principals`. That is what a Postgres-only design would do.

Two things make the store not Postgres-only. The Python enforcement point's
test suite runs against SQLite in-memory — `api-kaianolevine-com` builds its
whole 300-test suite on `sqlite+aiosqlite:///:memory:` — and SQLite has no
`CREATE SCHEMA`. And the TypeScript side of the ecosystem puts every table in
`public`, so a schema-qualified store would be the only thing in the database
that needed qualifying.

---

## Decision

The tables live in the default schema with an `identity_` name prefix:
`identity_principals`, `identity_roles`, `identity_audit_events`, and so on.
No `CREATE SCHEMA`, no schema qualification in any query, and the SQLAlchemy
models declare their own `IdentityBase` rather than borrowing a consuming
service's declarative base.

The prefix buys the same collision protection a schema would. What it does
not buy is schema-level privilege scoping.

---

## Consequences

**Positive:**

- The same DDL runs on Postgres and SQLite unchanged, so an enforcement
  point's test suite can host a real principal store rather than mocking the
  resolve step. That matters more than it sounds: the resolve step is where
  an issuer/subject pair becomes a principal, and mocking it is mocking the
  thing most likely to be wrong.
- Nothing in a consuming service's queries needs to know the store exists as
  a separate namespace.
- `IdentityBase` keeps the store's metadata separate from the host
  application's, so `create_all()` on one does not create the other's tables.

**Negative / trade-offs:**

- No `GRANT ... ON SCHEMA identity`. Least privilege on these tables has to
  be granted table by table, and a new table added later has to be
  remembered in that grant list or it silently inherits default privileges.
- The prefix is a convention, not a constraint. Nothing stops a future table
  from omitting it; only review catches that.
- Seven table names are eight characters longer than they need to be, in
  every query, forever.

---

## Alternatives Considered

**A Postgres schema.** Cleaner namespacing and real privilege scoping.
Rejected because it breaks SQLite, and SQLite is what lets an enforcement
point test its own binding end to end. Trading that for a GRANT convenience
is the wrong way round.

**No namespace at all.** Rejected on collision grounds — `roles` and
`principals` are names an application will want.

**Schema on Postgres, prefix on SQLite, resolved at runtime.** Rejected:
two DDLs mean the thing under test is not the thing that runs in production,
which defeats the reason for testing against a real store.
