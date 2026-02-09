/**
 * backend/src/shared/db/codegen.ts
 *
 * WHY:
 * - With Kysely, migrations define the database schema.
 * - We don't want to manually update TypeScript table types after every schema change.
 * - This script generates the `Database` interface directly from the REAL Postgres schema.
 *
 * HOW TO USE:
 * 1) Start infra and apply migrations:
 *      ./scripts/dev.sh
 * 2) Generate types:
 *      yarn workspace @auth-lab/backend db:types
 *
 * OUTPUT:
 * - Writes: src/shared/db/database.types.ts
 */
import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { execSync } from "node:child_process";
const EnvSchema = z.object({
    DATABASE_URL: z.string().min(1),
});
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// We generate types into this file:
const OUT_FILE = path.join(__dirname, "database.types.ts");
function main() {
    const env = EnvSchema.parse(process.env);
    // We call the official CLI under the hood so we don't reinvent it.
    // This keeps behavior consistent with the upstream tool.
    const cmd = [
        "kysely-codegen",
        "--dialect",
        "postgres",
        "--url",
        `"${env.DATABASE_URL}"`,
        "--out-file",
        `"${OUT_FILE}"`,
    ].join(" ");
    console.log("🔧 Generating Kysely Database types from Postgres schema...");
    console.log(`➡️  Output: ${OUT_FILE}`);
    execSync(cmd, { stdio: "inherit" });
    console.log("✅ Type generation complete.");
    console.log("Tip: If you changed schema, re-run db:types after migrations.");
}
main();
