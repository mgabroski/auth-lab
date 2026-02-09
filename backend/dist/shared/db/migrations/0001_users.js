import { sql } from "kysely";
export async function up(db) {
    await sql `CREATE EXTENSION IF NOT EXISTS "pgcrypto";`.execute(db);
    await db.schema
        .createTable("users")
        .addColumn("id", "uuid", (col) => col.primaryKey().defaultTo(sql `gen_random_uuid()`))
        .addColumn("email", "text", (col) => col.notNull().unique())
        .addColumn("password_hash", "text", (col) => col.notNull())
        .execute();
}
export async function down(db) {
    await db.schema.dropTable("users").ifExists().execute();
}
