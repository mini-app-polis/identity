# ADR-002: No Foreign Key From Audit Events to Principals

**Date:** 2026-09-02
**Status:** Accepted
**Repo:** identity

---

## Context

`identity_audit_events.principal_id` names the principal a decision was made
about. Every other cross-table reference in the store carries a foreign key:
`identity_principal_roles` to both principals and roles,
`identity_role_scopes` to roles.

The audit table is the exception, and the pull to make it consistent is
strong — a nullable UUID column that means "a principal" but is not declared
as one looks like an oversight, and will keep looking like one to every
reader who arrives after this.

---

## Decision

`identity_audit_events.principal_id` carries no foreign key to
`identity_principals`. It is a nullable UUID with an index, and nothing more.

The reason is the failure mode a foreign key would produce. With a
constraint, deleting a principal either cascades — erasing that principal's
audit history — or blocks the delete. Both are wrong. The moment a
principal's history matters most is precisely when someone has deleted it:
a compromised machine key revoked, a suspended account removed, an incident
being reconstructed. A constraint that makes the record disappear with its
subject is a constraint that erases the evidence on the schedule of whoever
caused the incident.

The column is also nullable by design. A decision can be made about a
credential that resolved to no principal at all — `principal_not_found` is a
first-class deny reason — and that denial is one of the more interesting
rows in the table. A non-null column could not record it.

---

## Consequences

**Positive:**

- Audit rows survive the deletion of their subject. Deleting a principal is
  a normal operation, not one that silently rewrites history.
- Denials for unknown principals are recordable, which is the case an
  intrusion looks like.
- The audit table takes no write-path lock on the principals table, so
  emitting an audit event cannot contend with principal reconciliation.

**Negative / trade-offs:**

- Referential integrity on this column is not enforced by the database. A
  bug that writes a garbage UUID produces an orphan row and nothing
  complains.
- Joining audit events to principals is an outer join whose right side may
  be absent, and every consumer has to handle that. A query that inner-joins
  will silently drop exactly the rows this decision exists to preserve.
- The column looks like a mistake. It needs the comment it carries in
  `models.py` and `sql/principal-store.sql`, and this ADR, to stop someone
  "fixing" it.

---

## Alternatives Considered

**Foreign key with `ON DELETE SET NULL`.** Preserves the row and satisfies
integrity. Rejected because it destroys the one field that makes the row
useful: an audit trail of decisions about `NULL` answers no question. It
also silently converts recoverable history into unrecoverable history at
delete time.

**Foreign key with `ON DELETE RESTRICT`, and never delete principals.**
Rejected: it makes principal deletion impossible in practice, which is a
real operation the store should support. Suspension covers the common case,
but "remove this entirely" has to remain available.

**Denormalise the principal's issuer and subject onto the audit row.**
Attractive — it would make the row self-describing and survive deletion by
construction. Rejected for now as a widening of the audit schema that has
not been needed; the `principal_id` plus the enforcement point and scope
have answered every question asked of the table so far. Worth revisiting if
reconstructing an incident turns out to need the identity inline.
