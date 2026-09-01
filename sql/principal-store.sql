-- The principal store: one schema, one instance per database.
--
-- Per ecosystem, not shared at runtime. The cogs + api-kaianolevine-com
-- database gets one of these; deejaytools-com gets its own. They share the
-- schema, never the rows. A shared runtime store would put a network hop and
-- a single point of failure back on the request path, which is the thing the
-- "one spec, N enforcement points" model exists to avoid.
--
-- Deployed into its own `identity` schema so it can be added to an existing
-- database without colliding with application tables, and so that grants can
-- be scoped to it separately.

CREATE SCHEMA IF NOT EXISTS identity;

-- Trusted issuers. Multi-issuer by design: the two Clerk tenants are
-- different products with different audiences and are never merged.
CREATE TABLE identity.issuers (
  issuer        TEXT PRIMARY KEY,
  display_name  TEXT NOT NULL DEFAULT '',
  jwks_url      TEXT NOT NULL,
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity.roles (
  name          TEXT PRIMARY KEY
                  CHECK (name ~ '^[a-z][a-z0-9-]*$'),
  description   TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Scopes are three dot-separated segments: <domain>.<resource>.<action>.
-- The CHECK is the schema's half of the same constraint the JSON Schema
-- enforces; both exist so a bad scope cannot enter through either door.
CREATE TABLE identity.role_scopes (
  role_name     TEXT NOT NULL REFERENCES identity.roles(name) ON DELETE CASCADE,
  scope         TEXT NOT NULL
                  CHECK (scope ~ '^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2}$'),
  PRIMARY KEY (role_name, scope)
);

CREATE TABLE identity.principals (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          TEXT NOT NULL CHECK (kind IN ('human', 'machine')),
  issuer        TEXT NOT NULL REFERENCES identity.issuers(issuer),
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

CREATE INDEX idx_principals_issuer_subject ON identity.principals(issuer, subject);
CREATE INDEX idx_principals_kind ON identity.principals(kind);

CREATE TABLE identity.principal_roles (
  principal_id  UUID NOT NULL REFERENCES identity.principals(id) ON DELETE CASCADE,
  role_name     TEXT NOT NULL REFERENCES identity.roles(name) ON DELETE RESTRICT,
  granted_by    TEXT NOT NULL DEFAULT '',
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, role_name)
);

-- Instance-level grants. Deliberately narrow: this is the shape
-- `wcs_note_grants` already has, generalized, not a general ACL system.
CREATE TABLE identity.explicit_grants (
  principal_id  UUID NOT NULL REFERENCES identity.principals(id) ON DELETE CASCADE,
  scope         TEXT NOT NULL
                  CHECK (scope ~ '^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2}$'),
  resource      TEXT NOT NULL,
  granted_by    TEXT NOT NULL DEFAULT '',
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, scope, resource)
);

-- Every decision, allow and deny alike. A trail that records only denials
-- cannot answer who did the thing.
CREATE TABLE identity.audit_events (
  event_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  enforcement_point  TEXT NOT NULL,
  principal_id       UUID REFERENCES identity.principals(id) ON DELETE SET NULL,
  principal_kind     TEXT CHECK (principal_kind IN ('human', 'machine')),
  issuer             TEXT,
  subject            TEXT,
  scope              TEXT NOT NULL,
  resource           TEXT,
  allowed            BOOLEAN NOT NULL,
  reason             TEXT NOT NULL,
  request_id         TEXT
);

CREATE INDEX idx_audit_events_occurred_at ON identity.audit_events(occurred_at DESC);
CREATE INDEX idx_audit_events_principal ON identity.audit_events(principal_id, occurred_at DESC);
CREATE INDEX idx_audit_events_enforcement_point ON identity.audit_events(enforcement_point, occurred_at DESC);
