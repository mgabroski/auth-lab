import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await sql`
    ALTER TABLE cp_accounts
      ADD CONSTRAINT cp_accounts_status_check
      CHECK (cp_status IN ('Draft', 'Active', 'Disabled'));
  `.execute(db);

  await sql`
    ALTER TABLE cp_accounts
      ADD CONSTRAINT cp_accounts_cp_revision_nonnegative_check
      CHECK (cp_revision >= 0);
  `.execute(db);

  await sql`
    ALTER TABLE cp_accounts
      ADD CONSTRAINT cp_accounts_account_key_format_check
      CHECK (account_key ~ '^[a-z0-9-]+$');
  `.execute(db);

  await sql`
    ALTER TABLE cp_personal_field_config
      ADD CONSTRAINT cp_personal_field_default_selected_requires_allowed_check
      CHECK ((NOT default_selected) OR is_allowed);
  `.execute(db);

  await sql`
    ALTER TABLE tenant_sections
      ADD CONSTRAINT tenant_sections_section_name_not_blank_check
      CHECK (length(btrim(section_name)) > 0);
  `.execute(db);

  await sql`
    ALTER TABLE tenant_sections
      ADD CONSTRAINT tenant_sections_sort_order_nonnegative_check
      CHECK (sort_order >= 0);
  `.execute(db);

  await sql`
    ALTER TABLE tenant_section_fields
      ADD CONSTRAINT tenant_section_fields_sort_order_nonnegative_check
      CHECK (sort_order >= 0);
  `.execute(db);
}

export async function down(db: Kysely<any>): Promise<void> {
  await sql`
    ALTER TABLE tenant_section_fields
      DROP CONSTRAINT IF EXISTS tenant_section_fields_sort_order_nonnegative_check;
  `.execute(db);

  await sql`
    ALTER TABLE tenant_sections
      DROP CONSTRAINT IF EXISTS tenant_sections_sort_order_nonnegative_check;
  `.execute(db);

  await sql`
    ALTER TABLE tenant_sections
      DROP CONSTRAINT IF EXISTS tenant_sections_section_name_not_blank_check;
  `.execute(db);

  await sql`
    ALTER TABLE cp_personal_field_config
      DROP CONSTRAINT IF EXISTS cp_personal_field_default_selected_requires_allowed_check;
  `.execute(db);

  await sql`
    ALTER TABLE cp_accounts
      DROP CONSTRAINT IF EXISTS cp_accounts_account_key_format_check;
  `.execute(db);

  await sql`
    ALTER TABLE cp_accounts
      DROP CONSTRAINT IF EXISTS cp_accounts_cp_revision_nonnegative_check;
  `.execute(db);

  await sql`
    ALTER TABLE cp_accounts
      DROP CONSTRAINT IF EXISTS cp_accounts_status_check;
  `.execute(db);
}
