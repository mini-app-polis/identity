-- The principal store: one schema, one instance per ecosystem database.
--
-- Per ecosystem, not shared at runtime. The cogs + api-kaianolevine-com
-- database gets one of these; deejaytools-com gets its own. They share the
-- shape, never the rows. A shared runtime store would put a network hop and
-- a single point of failure back on the request path, which is the thing the
-- "one spec, N enforcement points" model exists to avoid.
--
-- Tables are prefixed `identity_` in the default schema rather than living in
-- a Postgres schema of their own. The prefix buys the same namespacing; the
-- Postgres schema would have cost portability, because the Python
-- enforcement point's test suite runs against SQLite in-memory (SQLite has no
-- CREATE SCHEMA) and the TypeScript ecosystem's tables all live in `public`.
-- The trade is real: schema-level GRANT scoping is no longer available, so
-- least-privilege on these tables has to be granted table by table.

CREATE TABLE IF NOT EXISTS identity_issuers (
  issuer        TEXT PRIMARY KEY,
  display_name  TEXT NOT NULL DEFAULT '',
  jwks_url      TEXT NOT NULL,
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity_roles (
  name          TEXT PRIMARY KEY
                  CHECK (name ~ '^[a-z][a-z0-9-]*$'),
  description   TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Scopes are three dot-separated segments: <domain>.<resource>.<action>.
-- The CHECK is the database's half of the constraint the JSON Schema also
-- enforces; both exist so a malformed scope cannot enter through either door.
CREATE TABLE IF NOT EXISTS identity_role_scopes (
  role_name     TEXT NOT NULL REFERENCES identity_roles(name) ON DELETE CASCADE,
  scope         TEXT NOT NULL
                  CHECK (scope ~ '^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2}$'),
  PRIMARY KEY (role_name, scope)
);

CREATE TABLE IF NOT EXISTS identity_principals (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          TEXT NOT NULL CHECK (kind IN ('human', 'machine')),
  issuer        TEXT NOT NULL REFERENCES identity_issuers(issuer),
  subject       TEXT NOT NULL,
  display_name  TEXT NOT NULL DEFAULT '',
  email         TEXT,
  status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'suspended')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ,
  -- The issuer's subject is unique only within its issuer. This constraint is
  -- the whole reason `id` exists as a separate column: two Clerk tenants can
  -- legitimately mint the same `sub`.
  UNIQUE (issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_identity_principals_issuer_subject
  ON identity_principals(issuer, subject);
CREATE INDEX IF NOT EXISTS idx_identity_principals_kind
  ON identity_principals(kind);

CREATE TABLE IF NOT EXISTS identity_principal_roles (
  principal_id  UUID NOT NULL REFERENCES identity_principals(id) ON DELETE CASCADE,
  role_name     TEXT NOT NULL REFERENCES identity_roles(name) ON DELETE RESTRICT,
  granted_by    TEXT NOT NULL DEFAULT '',
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, role_name)
);

-- Instance-level grants. Deliberately narrow: this is the shape
-- `wcs_note_grants` already has, generalized, not a general ACL system.
CREATE TABLE IF NOT EXISTS identity_explicit_grants (
  principal_id  UUID NOT NULL REFERENCES identity_principals(id) ON DELETE CASCADE,
  scope         TEXT NOT NULL
                  CHECK (scope ~ '^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2}$'),
  resource      TEXT NOT NULL,
  granted_by    TEXT NOT NULL DEFAULT '',
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, scope, resource)
);

-- Every decision, allow and deny alike. A trail that records only denials
-- cannot answer who did the thing.
CREATE TABLE IF NOT EXISTS identity_audit_events (
  event_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  enforcement_point  TEXT NOT NULL,
  -- No foreign key: an audit event must survive deletion of the principal it
  -- describes, or the trail erases itself exactly when it matters most.
  principal_id       UUID,
  principal_kind     TEXT CHECK (principal_kind IN ('human', 'machine')),
  issuer             TEXT,
  subject            TEXT,
  scope              TEXT NOT NULL,
  resource           TEXT,
  allowed            BOOLEAN NOT NULL,
  reason             TEXT NOT NULL,
  request_id         TEXT
);

CREATE INDEX IF NOT EXISTS idx_identity_audit_occurred_at
  ON identity_audit_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_audit_principal
  ON identity_audit_events(principal_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_audit_enforcement_point
  ON identity_audit_events(enforcement_point, occurred_at DESC);
