/**
 * backend/src/index.ts
 *
 * WHY:
 * - Single entrypoint for the backend application.
 * - Keeps startup logic small: load config -> build server -> listen.
 *
 * HOW TO USE:
 * - Dev: `yarn dev` (runs via tsx watch)
 * - Later prod: `yarn build && yarn start` (runs dist/)
 */
import { buildConfig } from "./app/config";
import { buildServer } from "./app/server";
import { logger } from "./shared/logger/logger";
async function main() {
    const config = buildConfig();
    const app = await buildServer({ config });
    await app.listen({ port: config.port, host: "0.0.0.0" });
    logger.info(`API listening on port ${config.port}`);
}
main().catch((err) => {
    logger.error("Fatal startup error", { err });
    process.exit(1);
});
