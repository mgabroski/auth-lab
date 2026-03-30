#!/usr/bin/env node
/* global console */

/**
 * scripts/repo-guard.mjs
 *
 * Minimum viable Stage 1A repo guard.
 *
 * What it enforces:
 * 1. Approved prompt files must be listed in the prompt catalog.
 * 2. Changed backend route files must carry required API-doc updates in the same change.
 * 3. Minimum import-boundary violations are blocked.
 * 4. Protected law/governance file changes require linked update context in the PR body.
 * 5. PRs must keep the Module Quality Gate section present and mark applicability.
 * 6. Frontend same-origin discipline: browser/client code must not hardcode private backend
 *    origins or pull SSR-only transport into client components.
 *
 * Notes:
 * - This is intentionally lean. It blocks common silent-drift paths without pretending
 *   to replace human review, signoff, or branch protection.
 * - The current repo contains one known backend boundary exception. It is explicitly
 *   allowlisted here so Stage 1A can land honestly without fake cleanliness.
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { execFileSync } from 'node:child_process';

const ROOT = process.cwd();

const PROTECTED_LAW_FILES = [
  'docs/quality-bar.md',
  'AGENTS.md',
  'backend/AGENTS.md',
  'frontend/AGENTS.md',
  'code_review.md',
  'docs/ai/repo-ai-adoption-roadmap.md',
  'docs/prompts/catalog.md',
  'docs/prompts/usage-guide.md',
];

const ROUTE_DOC_COUPLING = new Map([
  ['backend/src/modules/auth/auth.routes.ts', 'backend/docs/api/auth.md'],
  ['backend/src/modules/invites/invite.routes.ts', 'backend/docs/api/invites.md'],
  ['backend/src/modules/invites/admin/admin-invite.routes.ts', 'backend/docs/api/admin.md'],
  ['backend/src/modules/audit/admin-audit.routes.ts', 'backend/docs/api/admin.md'],
]);

const BACKEND_SHARED_TO_MODULE_ALLOWLIST = new Set([
  'backend/src/shared/http/require-auth-context.ts -> backend/src/modules/memberships/membership.types.ts',
]);

const FRONTEND_PRIVATE_BACKEND_ALLOWLIST = new Set([
  'frontend/src/shared/ssr-api-client.ts',
  'frontend/src/app/api/[...path]/route.ts',
]);

const FRONTEND_PRIVATE_BACKEND_PATTERNS = [
  {
    label: 'localhost:3001 backend origin',
    regex: /https?:\/\/localhost:3001\b/,
  },
  {
    label: '127.0.0.1:3001 backend origin',
    regex: /https?:\/\/127\.0\.0\.1:3001\b/,
  },
  {
    label: 'backend:3001 Docker-internal origin',
    regex: /https?:\/\/backend:3001\b/,
  },
  {
    label: 'INTERNAL_API_URL usage',
    regex: /process\.env\.INTERNAL_API_URL\b/,
  },
];

main();

function main() {
  const changedEntries = getChangedEntries();
  const changedFiles = new Set(changedEntries.map((entry) => entry.path));
  const event = readGitHubEvent();
  const prBody = getPullRequestBody(event);

  const failures = [];
  const warnings = [];

  failures.push(...checkPromptCatalog());
  failures.push(...checkRouteDocCoupling(changedFiles));
  failures.push(...checkImportBoundaries());
  failures.push(...checkFrontendSameOriginDiscipline());

  const linkedUpdateContextResult = checkLinkedUpdateContext(changedFiles, prBody, event);
  failures.push(...linkedUpdateContextResult.failures);
  warnings.push(...linkedUpdateContextResult.warnings);

  const moduleQualityResult = checkModuleQualityGate(changedEntries, prBody, event);
  failures.push(...moduleQualityResult.failures);
  warnings.push(...moduleQualityResult.warnings);

  if (failures.length > 0) {
    console.error('\n❌ Repo guard failed.\n');
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }

    if (warnings.length > 0) {
      console.error('\nWarnings:');
      for (const warning of warnings) {
        console.error(`- ${warning}`);
      }
    }

    process.exit(1);
  }

  console.log('\n✅ Repo guard passed.');

  if (warnings.length > 0) {
    console.log('\nWarnings:');
    for (const warning of warnings) {
      console.log(`- ${warning}`);
    }
  }
}

function checkPromptCatalog() {
  const catalogPath = abs('docs/prompts/catalog.md');
  const promptsDir = abs('docs/prompts');

  if (!fs.existsSync(catalogPath) || !fs.existsSync(promptsDir)) {
    return [];
  }

  const catalog = fs.readFileSync(catalogPath, 'utf8');
  const promptFiles = fs
    .readdirSync(promptsDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) => name.endsWith('.md'))
    .filter((name) => name !== 'catalog.md' && name !== 'usage-guide.md')
    .sort();

  const failures = [];

  for (const promptFile of promptFiles) {
    const promptPath = `docs/prompts/${promptFile}`;
    if (!catalog.includes(`\`${promptPath}\``)) {
      failures.push(
        `Prompt file ${promptPath} exists but is missing from docs/prompts/catalog.md.`,
      );
    }
  }

  return failures;
}

function checkRouteDocCoupling(changedFiles) {
  const failures = [];

  for (const [routeFile, requiredDoc] of ROUTE_DOC_COUPLING.entries()) {
    if (changedFiles.has(routeFile) && !changedFiles.has(requiredDoc)) {
      failures.push(
        `Changed route file ${routeFile} requires a same-PR API-doc update to ${requiredDoc}.`,
      );
    }
  }

  return failures;
}

function checkImportBoundaries() {
  const failures = [];

  const backendFiles = walkCodeFiles(abs('backend/src'));
  const frontendFiles = walkCodeFiles(abs('frontend/src'));

  for (const file of backendFiles) {
    const relFile = toRepoPath(file);
    const imports = extractRelativeImports(file);

    for (const specifier of imports) {
      const resolved = resolveImportTarget(file, specifier);
      if (!resolved) {
        continue;
      }

      const relResolved = toRepoPath(resolved);

      if (
        relFile.startsWith('backend/src/shared/') &&
        relResolved.startsWith('backend/src/modules/')
      ) {
        const edge = `${relFile} -> ${relResolved}`;
        if (!BACKEND_SHARED_TO_MODULE_ALLOWLIST.has(edge)) {
          failures.push(
            `Backend boundary violation: shared/ must not import from modules/ (${edge}).`,
          );
        }
      }
    }
  }

  for (const file of frontendFiles) {
    const relFile = toRepoPath(file);
    const imports = extractRelativeImports(file);

    for (const specifier of imports) {
      const resolved = resolveImportTarget(file, specifier);
      if (!resolved) {
        continue;
      }

      const relResolved = toRepoPath(resolved);

      if (
        relFile.startsWith('frontend/src/shared/') &&
        relResolved.startsWith('frontend/src/app/')
      ) {
        failures.push(
          `Frontend boundary violation: frontend/src/shared/ must not import from frontend/src/app/ (${relFile} -> ${relResolved}).`,
        );
      }
    }
  }

  return failures;
}

function checkFrontendSameOriginDiscipline() {
  const failures = [];
  const frontendFiles = walkCodeFiles(abs('frontend/src'));

  for (const file of frontendFiles) {
    const relFile = toRepoPath(file);
    const content = fs.readFileSync(file, 'utf8');

    if (!FRONTEND_PRIVATE_BACKEND_ALLOWLIST.has(relFile)) {
      for (const pattern of FRONTEND_PRIVATE_BACKEND_PATTERNS) {
        if (pattern.regex.test(content)) {
          failures.push(
            `Frontend same-origin violation: ${relFile} must not reference ${pattern.label}. Browser/client-facing code must stay on same-origin /api/* paths.`,
          );
        }
      }
    }

    if (isClientComponentFile(content) && importsSsrApiClient(content)) {
      failures.push(
        `Frontend topology violation: client component ${relFile} must not import ssr-api-client. Client/browser code must use api-client.ts and same-origin /api/* paths.`,
      );
    }
  }

  return failures;
}

function checkLinkedUpdateContext(changedFiles, prBody, event) {
  const failures = [];
  const warnings = [];

  const protectedChanges = [...changedFiles].filter((file) => PROTECTED_LAW_FILES.includes(file));

  if (protectedChanges.length === 0) {
    return { failures, warnings };
  }

  if (!isPullRequestEvent(event)) {
    warnings.push(
      `Linked update context validation skipped outside pull_request event for protected files: ${protectedChanges.join(', ')}.`,
    );
    return { failures, warnings };
  }

  if (!prBody) {
    failures.push(
      `Protected files changed (${protectedChanges.join(', ')}), but PR body is missing.`,
    );
    return { failures, warnings };
  }

  const linkedContextSection = extractMarkdownSection(
    prBody,
    'Linked update context for protected law/governance files',
  );

  if (!linkedContextSection || isBlankOrNotApplicable(linkedContextSection)) {
    failures.push(
      `Protected files changed (${protectedChanges.join(', ')}), but the PR body does not contain a filled linked update context section.`,
    );
  }

  const governingDocsSection = extractMarkdownSection(prBody, 'Governing docs reviewed');
  if (!governingDocsSection || isBlankOrNotApplicable(governingDocsSection)) {
    failures.push(
      'Protected files changed, but the PR body does not contain a filled “Governing docs reviewed” section.',
    );
  }

  return { failures, warnings };
}

function checkModuleQualityGate(changedEntries, prBody, event) {
  const failures = [];
  const warnings = [];

  if (!isPullRequestEvent(event)) {
    warnings.push('Module Quality Gate validation skipped: Not a PR event.');
    return { failures, warnings };
  }

  if (!prBody) {
    failures.push(
      'PR body is empty. The Module Quality Gate section must be present in the PR description.',
    );
    return { failures, warnings };
  }

  const moduleQualitySection = extractMarkdownSection(prBody, 'Module Quality Gate');
  if (!moduleQualitySection) {
    failures.push('PR body is missing the “Module Quality Gate” section.');
    return { failures, warnings };
  }

  const notApplicableChecked = /- \[[xX]\] Not applicable/m.test(moduleQualitySection);
  const applicableChecked = /- \[[xX]\] Applicable/m.test(moduleQualitySection);

  if (!notApplicableChecked && !applicableChecked) {
    failures.push(
      'Module Quality Gate section exists, but neither “Applicable” nor “Not applicable” is checked.',
    );
  }

  if (notApplicableChecked && applicableChecked) {
    failures.push(
      'Module Quality Gate section cannot have both “Applicable” and “Not applicable” checked.',
    );
  }

  if (isLikelyMajorModuleWork(changedEntries) && !applicableChecked) {
    failures.push(
      'This PR looks like likely major-module work, but the Module Quality Gate is not marked as applicable.',
    );
  }

  return { failures, warnings };
}

function isLikelyMajorModuleWork(changedEntries) {
  return changedEntries.some((entry) => {
    if (
      entry.status === 'A' &&
      /^backend\/src\/modules\/[^/]+\/[^/]+\.module\.ts$/.test(entry.path)
    ) {
      return true;
    }

    if (entry.status === 'A' && /^backend\/docs\/api\/[^/]+\.md$/.test(entry.path)) {
      return true;
    }

    return false;
  });
}

function getChangedEntries() {
  const event = readGitHubEvent();
  const baseSha = event?.pull_request?.base?.sha ?? process.env.GITHUB_BASE_SHA ?? null;
  const headSha = event?.pull_request?.head?.sha ?? process.env.GITHUB_HEAD_SHA ?? 'HEAD';

  let output = '';

  try {
    if (baseSha) {
      output = git(['diff', '--name-status', baseSha, headSha]);
    } else {
      output = git(['diff', '--name-status', 'HEAD~1', 'HEAD']);
    }
  } catch {
    output = git(['diff', '--name-status', 'HEAD']);
  }

  return output
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map(parseNameStatusLine)
    .filter(Boolean);
}

function parseNameStatusLine(line) {
  const parts = line.split(/\s+/);
  const status = parts[0];

  if (!status) {
    return null;
  }

  if (status.startsWith('R') || status.startsWith('C')) {
    const nextPath = parts[2];
    if (!nextPath) {
      return null;
    }
    return { status: status[0], path: normalizeRepoPath(nextPath) };
  }

  const nextPath = parts[1];
  if (!nextPath) {
    return null;
  }

  return { status: status[0], path: normalizeRepoPath(nextPath) };
}

function readGitHubEvent() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath || !fs.existsSync(eventPath)) {
    return null;
  }

  try {
    return JSON.parse(fs.readFileSync(eventPath, 'utf8'));
  } catch {
    return null;
  }
}

function getPullRequestBody(event) {
  return event?.pull_request?.body?.trim() ?? '';
}

function isPullRequestEvent(event) {
  return Boolean(event?.pull_request);
}

function extractMarkdownSection(markdown, headingText) {
  const escapedHeading = escapeRegExp(headingText);
  const pattern = new RegExp(
    String.raw`^##\s+${escapedHeading}\s*$([\s\S]*?)(?=^##\s+|^#\s+|\Z)`,
    'm',
  );
  const match = markdown.match(pattern);
  return match?.[1]?.trim() ?? '';
}

function isBlankOrNotApplicable(value) {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.length === 0 || normalized === 'not applicable.' || normalized === 'not applicable'
  );
}

function walkCodeFiles(startDir) {
  if (!fs.existsSync(startDir)) {
    return [];
  }

  const results = [];
  const stack = [startDir];

  while (stack.length > 0) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }

      if (/\.(ts|tsx|mts|cts)$/.test(entry.name)) {
        results.push(fullPath);
      }
    }
  }

  return results;
}

function extractRelativeImports(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const matches = [];
  const pattern =
    /(?:import|export)\s+(?:[^'"()]*?\s+from\s+)?['"](\.[^'"]+)['"]|import\(\s*['"](\.[^'"]+)['"]\s*\)/g;

  let match;
  while ((match = pattern.exec(content)) !== null) {
    const specifier = match[1] ?? match[2];
    if (specifier) {
      matches.push(specifier);
    }
  }

  return matches;
}

function resolveImportTarget(fromFile, specifier) {
  const basePath = path.resolve(path.dirname(fromFile), specifier);
  const candidates = [
    basePath,
    `${basePath}.ts`,
    `${basePath}.tsx`,
    `${basePath}.mts`,
    `${basePath}.cts`,
    path.join(basePath, 'index.ts'),
    path.join(basePath, 'index.tsx'),
    path.join(basePath, 'index.mts'),
    path.join(basePath, 'index.cts'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }

  return null;
}

function isClientComponentFile(content) {
  return /^\s*['"]use client['"]\s*;?/m.test(content);
}

function importsSsrApiClient(content) {
  return /(?:import|export)\s+(?:[^'"()]*?\s+from\s+)?['"][^'"]*ssr-api-client['"]/.test(content);
}

function git(args) {
  return execFileSync('git', args, {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function abs(repoPath) {
  return path.join(ROOT, repoPath);
}

function toRepoPath(filePath) {
  return normalizeRepoPath(path.relative(ROOT, filePath));
}

function normalizeRepoPath(filePath) {
  return filePath.split(path.sep).join('/');
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
