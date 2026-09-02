# Architecture Decision Records

Decisions specific to this library — why the contract and its store are
shaped the way they are. The ecosystem-wide decision that produced this
library is **ADR-008 (Named Machine Keys as the Machine Identity)** in
`ecosystem-standards`; the rules derived from it are CD-019, AUTH-003
and AUTH-004.

---

## Index

| ID      | Status   | Title                                                        |
|---------|----------|--------------------------------------------------------------|
| ADR-001 | Accepted | [Prefixed Tables Over a Postgres Schema](ADR-001-prefixed-tables-over-postgres-schema.md) |
| ADR-002 | Accepted | [No Foreign Key From Audit Events to Principals](ADR-002-no-foreign-key-from-audit-to-principals.md) |

---

## Summaries

**ADR-001 — Prefixed Tables Over a Postgres Schema.**
The store's seven tables carry names an application is entitled to want
for itself (`roles`, `principals`), so they need a namespace. A Postgres
schema is the obvious tool and was rejected: SQLite has no
`CREATE SCHEMA`, and the Python enforcement point's whole test suite
runs on SQLite in-memory — so a schema-qualified store could not be
exercised end to end by the service binding it. Mocking the resolve step
means mocking the part most likely to be wrong. The `identity_` prefix
buys the same collision protection; the cost is schema-level `GRANT`
scoping, which now has to be granted table by table.

**ADR-002 — No Foreign Key From Audit Events to Principals.**
`identity_audit_events.principal_id` looks like an oversight and will
keep looking like one, which is why it needed writing down. A foreign
key would either cascade the delete and erase a principal's history, or
block the delete outright. The moment that history matters most is
exactly when someone has deleted the principal — a revoked machine key,
a removed account, an incident being reconstructed. The column is
nullable for a related reason: `principal_not_found` is a first-class
deny reason, and a denial for a credential that resolved to nobody is
one of the more interesting rows in the table.

---

## Status legend

- **Proposed** — drafted but not yet committed to.
- **Accepted** — the library operates on this decision.
- **Superseded** — replaced by a later ADR. The file stays in place with
  a `**Superseded by:** ADR-NNN` line in its header.

See `ecosystem-standards/playbooks/new-adr.md` for the process.
