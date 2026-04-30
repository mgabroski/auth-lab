import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema
    .createTable('tenant_personal_family_state')
    .addColumn('tenant_id', 'uuid', (col) =>
      col.notNull().references('tenants.id').onDelete('cascade'),
    )
    .addColumn('family_key', 'text', (col) => col.notNull())
    .addColumn('review_decision', 'text', (col) => col.notNull())
    .addColumn('applied_cp_revision', 'integer', (col) => col.notNull().defaultTo(0))
    .addColumn('last_saved_at', 'timestamptz')
    .addColumn('last_saved_by_user_id', 'uuid', (col) =>
      col.references('users.id').onDelete('set null'),
    )
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addPrimaryKeyConstraint('tenant_personal_family_state_pkey', ['tenant_id', 'family_key'])
    .addCheckConstraint(
      'tenant_personal_family_state_review_decision_check',
      sql`review_decision in ('IN_USE', 'EXCLUDED')`,
    )
    .execute();

  await db.schema
    .createTable('tenant_field_config')
    .addColumn('tenant_id', 'uuid', (col) =>
      col.notNull().references('tenants.id').onDelete('cascade'),
    )
    .addColumn('field_key', 'text', (col) => col.notNull())
    .addColumn('family_key', 'text', (col) => col.notNull())
    .addColumn('included', 'boolean', (col) => col.notNull().defaultTo(false))
    .addColumn('required', 'boolean', (col) => col.notNull().defaultTo(false))
    .addColumn('masked', 'boolean', (col) => col.notNull().defaultTo(false))
    .addColumn('applied_cp_revision', 'integer', (col) => col.notNull().defaultTo(0))
    .addColumn('last_saved_at', 'timestamptz')
    .addColumn('last_saved_by_user_id', 'uuid', (col) =>
      col.references('users.id').onDelete('set null'),
    )
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addPrimaryKeyConstraint('tenant_field_config_pkey', ['tenant_id', 'field_key'])
    .execute();

  await db.schema
    .createTable('tenant_sections')
    .addColumn('tenant_id', 'uuid', (col) =>
      col.notNull().references('tenants.id').onDelete('cascade'),
    )
    .addColumn('section_id', 'text', (col) => col.notNull())
    .addColumn('section_name', 'text', (col) => col.notNull())
    .addColumn('sort_order', 'integer', (col) => col.notNull().defaultTo(0))
    .addColumn('applied_cp_revision', 'integer', (col) => col.notNull().defaultTo(0))
    .addColumn('last_saved_at', 'timestamptz')
    .addColumn('last_saved_by_user_id', 'uuid', (col) =>
      col.references('users.id').onDelete('set null'),
    )
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addColumn('updated_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addPrimaryKeyConstraint('tenant_sections_pkey', ['tenant_id', 'section_id'])
    .execute();

  await db.schema
    .createTable('tenant_section_fields')
    .addColumn('tenant_id', 'uuid', (col) =>
      col.notNull().references('tenants.id').onDelete('cascade'),
    )
    .addColumn('section_id', 'text', (col) => col.notNull())
    .addColumn('field_key', 'text', (col) => col.notNull())
    .addColumn('sort_order', 'integer', (col) => col.notNull().defaultTo(0))
    .addColumn('created_at', 'timestamptz', (col) => col.notNull().defaultTo(sql`now()`))
    .addPrimaryKeyConstraint('tenant_section_fields_pkey', ['tenant_id', 'section_id', 'field_key'])
    .execute();

  await db.schema
    .alterTable('tenant_section_fields')
    .addForeignKeyConstraint(
      'tenant_section_fields_section_fkey',
      ['tenant_id', 'section_id'],
      'tenant_sections',
      ['tenant_id', 'section_id'],
    )
    .onDelete('cascade')
    .execute();

  await db.schema
    .alterTable('tenant_section_fields')
    .addForeignKeyConstraint(
      'tenant_section_fields_field_fkey',
      ['tenant_id', 'field_key'],
      'tenant_field_config',
      ['tenant_id', 'field_key'],
    )
    .onDelete('cascade')
    .execute();

  await db.schema
    .createIndex('tenant_field_config_tenant_family_idx')
    .on('tenant_field_config')
    .columns(['tenant_id', 'family_key'])
    .execute();

  await db.schema
    .createIndex('tenant_sections_tenant_order_idx')
    .on('tenant_sections')
    .columns(['tenant_id', 'sort_order'])
    .execute();

  await db.schema
    .createIndex('tenant_section_fields_tenant_section_order_idx')
    .on('tenant_section_fields')
    .columns(['tenant_id', 'section_id', 'sort_order'])
    .execute();

  await db.schema
    .createIndex('tenant_section_fields_tenant_field_unique_idx')
    .on('tenant_section_fields')
    .columns(['tenant_id', 'field_key'])
    .unique()
    .execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.dropIndex('tenant_section_fields_tenant_field_unique_idx').ifExists().execute();
  await db.schema.dropIndex('tenant_section_fields_tenant_section_order_idx').ifExists().execute();
  await db.schema.dropIndex('tenant_sections_tenant_order_idx').ifExists().execute();
  await db.schema.dropIndex('tenant_field_config_tenant_family_idx').ifExists().execute();

  await db.schema.dropTable('tenant_section_fields').ifExists().execute();
  await db.schema.dropTable('tenant_sections').ifExists().execute();
  await db.schema.dropTable('tenant_field_config').ifExists().execute();
  await db.schema.dropTable('tenant_personal_family_state').ifExists().execute();
}
