import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  // Preserve the locked global-user invariant: one normalized email = one user.
  // Application flows already lower-case emails; this DB constraint prevents a
  // future import/manual insert path from creating case-variant identities.
  await sql`UPDATE users SET email = lower(email) WHERE email <> lower(email);`.execute(db);

  await sql`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_email_lowercase_check'
      ) THEN
        ALTER TABLE users
          ADD CONSTRAINT users_email_lowercase_check CHECK (email = lower(email));
      END IF;
    END $$;
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_lowercase_check;`.execute(db);
}
