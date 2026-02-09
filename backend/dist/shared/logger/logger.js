/**
 * backend/src/shared/logger/logger.ts
 *
 * WHY:
 * - Central logger instance (structured logs).
 * - Keeps logging consistent across app/modules.
 *
 * HOW TO USE:
 * - Import `logger` anywhere you need logs.
 * - Later we can attach request context (requestId, tenantId) cleanly.
 */
import winston from "winston";
export const logger = winston.createLogger({
    level: "info",
    format: winston.format.json(),
    transports: [new winston.transports.Console()],
});
