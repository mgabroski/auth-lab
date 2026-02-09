/**
 * src/shared/db/migrations/0002_core_auth_schema.ts
 *
 * WHY:
 * - Evolve from a "toy users table" to the real Hubins/Auth-Lab domain model:
 *   tenants (workspaces), memberships, auth identities (password/SSO),
 *   invites, password resets, and audit events.
 *
 * HOW TO USE:
 * - Run all migrations:
 *     yarn workspace @auth-lab/backend db:migrate
 * - Then regenerate Kysely types:
 *     yarn workspace @auth-lab/backend db:types
 */

import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  // Ensure pgcrypto exists (gen_random_uuid)
  await sql`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`.execute(db);

  // ---- users (global identity) ----
  // Move password_hash out of users (SSO users won't have one).
  await db.schema
    .alterTable('users')
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .execute();

  // Drop legacy password_hash column from users (now belongs to auth_identities)
  await db.schema.alterTable('users').dropColumn('password_hash').execute();

  // ---- tenants (workspaces) ----
  await db.schema
    .createTable('tenants')
    .addColumn('id', 'uuid', (col) => col.primaryKey().defaultTo(sql`gen_random_uuid()`))
    // tenant key = subdomain/workspace key (e.g. goodwill-ca). Used for routing.
    .addColumn('key', 'text', (col) => col.notNull().unique())
    .addColumn('name', 'text', (col) => col.notNull())
    .addColumn('is_active', 'boolean', (col) => col.notNull().defaultTo(true))
    .addColumn('public_signup_enabled', 'boolean', (col) => col.notNull().defaultTo(false))
    .addColumn('member_mfa_required', 'boolean', (col) => col.notNull().defaultTo(false))
    // Optional: restrict signup/invites to certain domains (kept simple as JSON array for now)
    .addColumn('allowed_email_domains', 'jsonb', (col) => col.notNull().defaultTo(sql`'[]'::jsonb`))
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .execute();

  // ---- memberships (User <-> Tenant link; access is decided here) ----
  await db.schema
    .createTable('memberships')
    .addColumn('id', 'uuid', (col) => col.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn('tenant_id', 'uuid', (col) =>
      col.notNull().references('tenants.id').onDelete('cascade'),
    )
    .addColumn('user_id', 'uuid', (col) => col.notNull().references('users.id').onDelete('cascade'))
    .addColumn('role', 'text', (col) => col.notNull())
    .addColumn('status', 'text', (col) => col.notNull())
    .addColumn('invited_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addColumn('accepted_at', 'timestamptz')
    .addColumn('suspended_at', 'timestamptz')
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .execute();

  // Enforce allowed values (kept as CHECK constraints; pragmatic & easy to migrate)
  await sql`
    ALTER TABLE memberships
      ADD CONSTRAINT memberships_role_check
      CHECK (role IN ('ADMIN','MEMBER'));
  `.execute(db);

  await sql`
    ALTER TABLE memberships
      ADD CONSTRAINT memberships_status_check
      CHECK (status IN ('INVITED','ACTIVE','SUSPENDED'));
  `.execute(db);

  // A user can belong to a tenant only once
  await sql`
    ALTER TABLE memberships
      ADD CONSTRAINT memberships_tenant_user_unique
      UNIQUE (tenant_id, user_id);
  `.execute(db);

  await sql`CREATE INDEX memberships_tenant_id_idx ON memberships(tenant_id);`.execute(db);
  await sql`CREATE INDEX memberships_user_id_idx ON memberships(user_id);`.execute(db);

  // ---- auth_identities (password/google/microsoft) ----
  await db.schema
    .createTable('auth_identities')
    .addColumn('id', 'uuid', (col) => col.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn('user_id', 'uuid', (col) => col.notNull().references('users.id').onDelete('cascade'))
    .addColumn('provider', 'text', (col) => col.notNull()) // password|google|microsoft
    .addColumn('provider_subject', 'text') // sub/oid for SSO
    .addColumn('password_hash', 'text') // only for provider=password
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .execute();

  await sql`
    ALTER TABLE auth_identities
      ADD CONSTRAINT auth_identities_provider_check
      CHECK (provider IN ('password','google','microsoft'));
  `.execute(db);

  // One identity per user per provider
  await sql`
    ALTER TABLE auth_identities
      ADD CONSTRAINT auth_identities_user_provider_unique
      UNIQUE (user_id, provider);
  `.execute(db);

  // SSO subject must be unique per provider (when present)
  await sql`
    CREATE UNIQUE INDEX auth_identities_provider_subject_unique
    ON auth_identities(provider, provider_subject)
    WHERE provider_subject IS NOT NULL;
  `.execute(db);

  // Password identity must have password_hash; SSO identities must not rely on it
  await sql`
    ALTER TABLE auth_identities
      ADD CONSTRAINT auth_identities_password_require_hash
      CHECK (
        (provider = 'password' AND password_hash IS NOT NULL AND provider_subject IS NULL)
        OR
        (provider IN ('google','microsoft') AND provider_subject IS NOT NULL)
      );
  `.execute(db);

  // ---- invites (provisioning entry point) ----
  await db.schema
    .createTable('invites')
    .addColumn('id', 'uuid', (col) => col.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn('tenant_id', 'uuid', (col) =>
      col.notNull().references('tenants.id').onDelete('cascade'),
    )
    .addColumn('email', 'text', (col) => col.notNull())
    .addColumn('role', 'text', (col) => col.notNull())
    .addColumn('status', 'text', (col) => col.notNull()) // PENDING|ACCEPTED|CANCELLED|EXPIRED
    .addColumn('token_hash', 'text', (col) => col.notNull()) // SHA-256 hash only
    .addColumn('expires_at', 'timestamptz', (col) => col.notNull())
    .addColumn('used_at', 'timestamptz')
    .addColumn('created_by_user_id', 'uuid', (col) =>
      col.references('users.id').onDelete('set null'),
    )
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .execute();

  await sql`
    ALTER TABLE invites
      ADD CONSTRAINT invites_role_check
      CHECK (role IN ('ADMIN','MEMBER'));
  `.execute(db);

  await sql`
    ALTER TABLE invites
      ADD CONSTRAINT invites_status_check
      CHECK (status IN ('PENDING','ACCEPTED','CANCELLED','EXPIRED'));
  `.execute(db);

  await sql`CREATE UNIQUE INDEX invites_token_hash_unique ON invites(token_hash);`.execute(db);
  await sql`CREATE INDEX invites_tenant_id_idx ON invites(tenant_id);`.execute(db);
  await sql`CREATE INDEX invites_email_idx ON invites(email);`.execute(db);

  // ---- password_reset_tokens ----
  await db.schema
    .createTable('password_reset_tokens')
    .addColumn('id', 'uuid', (col) => col.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn('user_id', 'uuid', (col) => col.notNull().references('users.id').onDelete('cascade'))
    .addColumn('token_hash', 'text', (col) => col.notNull())
    .addColumn('expires_at', 'timestamptz', (col) => col.notNull())
    .addColumn('used_at', 'timestamptz')
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .execute();

  await sql`
    CREATE UNIQUE INDEX password_reset_tokens_token_hash_unique
    ON password_reset_tokens(token_hash);
  `.execute(db);

  await sql`CREATE INDEX password_reset_tokens_user_id_idx ON password_reset_tokens(user_id);`.execute(
    db,
  );

  // ---- audit_events (append-only) ----
  await db.schema
    .createTable('audit_events')
    .addColumn('id', 'uuid', (col) => col.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn('tenant_id', 'uuid') // may be null for pre-tenant actions; keep nullable if needed later
    .addColumn('user_id', 'uuid')
    .addColumn('membership_id', 'uuid')
    .addColumn('action', 'text', (col) => col.notNull())
    .addColumn('request_id', 'text')
    .addColumn('ip', 'text')
    .addColumn('user_agent', 'text')
    .addColumn('metadata', 'jsonb', (col) => col.notNull().defaultTo(sql`'{}'::jsonb`))
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .execute();

  await sql`CREATE INDEX audit_events_tenant_id_idx ON audit_events(tenant_id);`.execute(db);
  await sql`CREATE INDEX audit_events_user_id_idx ON audit_events(user_id);`.execute(db);
  await sql`CREATE INDEX audit_events_action_idx ON audit_events(action);`.execute(db);
  await sql`CREATE INDEX audit_events_created_at_idx ON audit_events(created_at);`.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  // Drop in reverse dependency order
  await db.schema.dropTable('audit_events').ifExists().execute();
  await db.schema.dropTable('password_reset_tokens').ifExists().execute();
  await db.schema.dropTable('invites').ifExists().execute();
  await db.schema.dropTable('auth_identities').ifExists().execute();
  await db.schema.dropTable('memberships').ifExists().execute();
  await db.schema.dropTable('tenants').ifExists().execute();

  // Revert users changes (best effort)
  await db.schema
    .alterTable('users')
    .addColumn('password_hash', 'text') // nullable on rollback to avoid failing existing rows
    .execute();

  await db.schema.alterTable('users').dropColumn('created_at').execute();
  await db.schema.alterTable('users').dropColumn('updated_at').execute();
}
