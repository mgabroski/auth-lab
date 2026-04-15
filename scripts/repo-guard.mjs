#!/usr/bin/env node
/* global console */

/**
 * scripts/repo-guard.mjs
 *
 * Stage 1A + Stage 1B repo guard, extended for stronger Track A enforcement depth.
 *
 * What it enforces:
 * 1. Approved prompt files must be listed in the prompt catalog.
 * 2. Changed backend route files must carry required API-doc updates in the same change.
 * 3. Minimum import-boundary violations are blocked.
 * 4. Protected law/governance file changes require linked update context in the PR body.
 * 5. Likely major-module work must not silently skip the Module Quality Gate path.
 * 6. Major-module PRs must provide stronger evidence sections, signoff tracking,
 *    and quality-exception visibility.
 * 7. Architecture-law / ADR-sensitive changes must provide explicit ADR linkage handling.
 * 8. Frontend same-origin discipline remains enforced.
 * 8a. CP package must not import from frontend/src/. CP same-origin discipline enforced.
 * 9. Release / change-management expectations remain enforced.
 * 10. Selective auth/invite message-surface changes must update the user-visible
 *     message audit in the same PR.
 * 11. CI emits a summary for drift, exception, and waiver visibility.
 *
 * Notes:
 * - This guard is intentionally repo-native. It does not pretend to replace branch
 *   protection, required reviewers in GitHub settings, or human judgment.
 * - It biases toward blocking silent drift and making exceptions reviewer-visible.
 * - One known backend boundary exception remains explicitly allowlisted.
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { execFileSync } from 'node:child_process';

const ROOT = process.cwd();
const QUALITY_EXCEPTIONS_FILE = 'docs/quality-exceptions.md';
const AUTH_MESSAGE_AUDIT_FILE = 'docs/qa/auth-message-audit.md';
const CHANGELOG_FILE = 'CHANGELOG.md';

const PROTECTED_LAW_FILES = [
  'docs/quality-bar.md',
  'docs/quality-exceptions.md',
  'docs/current-foundation-status.md',
  'docs/ops/release-engineering.md',
  'AGENTS.md',
  'backend/AGENTS.md',
  'frontend/AGENTS.md',
  'code_review.md',
  'docs/prompts/catalog.md',
  'docs/prompts/usage-guide.md',
  '.github/CODEOWNERS',
  '.github/pull_request_template.md',
  'scripts/repo-guard.mjs',
];

const ROUTE_DOC_COUPLING = new Map([
  ['backend/src/modules/auth/auth.routes.ts', 'backend/docs/api/auth.md'],
  ['backend/src/modules/invites/invite.routes.ts', 'backend/docs/api/invites.md'],
  ['backend/src/modules/invites/admin/admin-invite.routes.ts', 'backend/docs/api/admin.md'],
  ['backend/src/modules/audit/admin-audit.routes.ts', 'backend/docs/api/admin.md'],
  [
    'backend/src/modules/control-plane/accounts/cp-accounts.routes.ts',
    'backend/docs/api/cp-accounts.md',
  ],
]);

const ROUTE_FILE_PATTERN = /^backend\/src\/modules\/.+\.routes\.ts$/;
const API_DOC_PATTERN = /^backend\/docs\/api\/.+\.md$/;
const ADR_FILE_PATTERN = /^backend\/docs\/adr\/.+\.md$/;
const DECISION_LOG_FILE = 'docs/decision-log.md';

const ARCHITECTURE_LAW_PATTERNS = [
  /^docs\/quality-bar\.md$/,
  /^docs\/quality-exceptions\.md$/,
  /^docs\/current-foundation-status\.md$/,
  /^ARCHITECTURE\.md$/,
  /^backend\/docs\/adr\/.+\.md$/,
  /^docs\/decision-log\.md$/,
  /^infra\/caddy\/Caddyfile$/,
  /^infra\/nginx\/nginx\.conf$/,
  /^frontend\/src\/app\/api\/\[\.\.\.path\]\/route\.ts$/,
  /^frontend\/src\/shared\/api-client\.ts$/,
  /^frontend\/src\/shared\/ssr-api-client\.ts$/,
  /^frontend\/src\/shared\/auth\/bootstrap\.server\.ts$/,
  /^backend\/src\/shared\/http\//,
  /^backend\/src\/shared\/session\//,
  /^backend\/src\/modules\/auth\//,
  /^backend\/src\/modules\/invites\//,
  /^backend\/src\/modules\/tenants\//,
  /^backend\/src\/modules\/memberships\//,
  /^\.github\/CODEOWNERS$/,
  /^\.github\/pull_request_template\.md$/,
  /^scripts\/repo-guard\.mjs$/,
];

const AUTH_MESSAGE_AUDIT_TRIGGERS = [
  /^backend\/src\/modules\/auth\/auth\.controller\.ts$/,
  /^backend\/src\/modules\/auth\/auth\.errors\.ts$/,
  /^backend\/src\/modules\/auth\/auth\.service\.ts$/,
  /^backend\/src\/modules\/invites\/invite\.controller\.ts$/,
  /^backend\/src\/modules\/invites\/invite\.errors\.ts$/,
  /^backend\/src\/modules\/invites\/invite\.service\.ts$/,
  /^backend\/src\/modules\/invites\/admin\/admin-invite\.controller\.ts$/,
  /^backend\/src\/modules\/invites\/admin\/admin-invite\.errors\.ts$/,
  /^backend\/src\/modules\/invites\/admin\/admin-invite\.service\.ts$/,
  /^backend\/src\/shared\/http\/error-handler\.ts$/,
  /^backend\/src\/shared\/http\/errors\.ts$/,
];

const BACKEND_SHARED_TO_MODULE_ALLOWLIST = new Set([
  'backend/src/shared/http/require-auth-context.ts -> backend/src/modules/memberships/membership.types.ts',
]);

const FRONTEND_PRIVATE_BACKEND_ALLOWLIST = new Set([
  'frontend/src/shared/ssr-api-client.ts',
  'frontend/src/app/api/[...path]/route.ts',
]);

// WHY: These two CP files are the intentional same-origin infrastructure files
// that may reference INTERNAL_API_URL / localhost:3001 as a fallback only.
// They mirror the pattern of their frontend equivalents and are the only CP
// files permitted to reference the backend origin directly.
const CP_PRIVATE_BACKEND_ALLOWLIST = new Set([
  'cp/src/shared/cp/ssr-api-client.ts',
  'cp/src/app/api/[...path]/route.ts',
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

// WHY: CP is a separate package that must never import from the tenant frontend.
// The boundary is enforced here so a Phase 2 engineer cannot accidentally
// pull frontend/src/ modules into cp/src/ and blur the separation.
const CP_FRONTEND_IMPORT_PATTERNS = [
  {
    label: 'import from frontend/src/',
    regex: /from\s+['"][^'"]*frontend\/src\//,
  },
  {
    label: 'require from frontend/src/',
    regex: /require\s*\(\s*['"][^'"]*frontend\/src\//,
  },
];

// WHY: CP must not call the backend directly with hardcoded origins in Phase 2+.
// Same-origin discipline applies to CP just as it does to the tenant frontend.
// CP API calls must go through the proxy or through CP-scoped /api/* routes.
const CP_PRIVATE_BACKEND_PATTERNS = [
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
];

const MODULE_APPLICABILITY_LABELS = [
  'Not applicable — this PR does not introduce or substantially expand a major module',
  'Applicable — this PR introduces or substantially expands a major module',
];

const ADR_LINKAGE_LABELS = [
  'ADR updated in this PR',
  'New ADR added in this PR',
  'Decision log updated in this PR',
  'No ADR or decision-log update required',
];

const RELEASE_LANE_LABELS = [
  'Lane A — standard code/doc change',
  'Lane B — topology / auth / security-sensitive change',
  'Lane C — migration-bearing change',
  'Lane D — hotfix',
];

const CHANGELOG_IMPACT_LABELS = ['CHANGELOG.md updated in this PR', 'No changelog entry required'];

const MIGRATION_PATH_PATTERNS = [/^backend\/src\/shared\/db\/migrations\//];

main();

function main() {
  const changedEntries = getChangedEntries();
  const changedFiles = new Set(changedEntries.map((entry) => entry.path));
  const event = readGitHubEvent();
  const prBody = getPullRequestBody(event);

  const context = buildContext(changedEntries, changedFiles, event, prBody);

  const failures = [];
  const warnings = [];

  failures.push(...checkPromptCatalog());
  failures.push(...checkRouteDocCoupling(context));
  failures.push(...checkImportBoundaries());
  failures.push(...checkFrontendSameOriginDiscipline());
  failures.push(...checkCpBoundaries());

  const linkedUpdateContextResult = checkLinkedUpdateContext(context);
  failures.push(...linkedUpdateContextResult.failures);
  warnings.push(...linkedUpdateContextResult.warnings);

  const architectureLinkageResult = checkArchitectureLawLinkage(context);
  failures.push(...architectureLinkageResult.failures);
  warnings.push(...architectureLinkageResult.warnings);

  const moduleQualityResult = checkModuleQualityGate(context);
  failures.push(...moduleQualityResult.failures);
  warnings.push(...moduleQualityResult.warnings);

  const releaseManagementResult = checkReleaseManagement(context);
  failures.push(...releaseManagementResult.failures);
  warnings.push(...releaseManagementResult.warnings);

  failures.push(...checkSelectiveErrorMessageAudit(context));

  writeSummary(context, failures, warnings);

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

function buildContext(changedEntries, changedFiles, event, prBody) {
  const protectedChanges = [...changedFiles].filter((file) => PROTECTED_LAW_FILES.includes(file));
  const routeFilesChanged = [...changedFiles].filter((file) => ROUTE_FILE_PATTERN.test(file));
  const apiDocsChanged = [...changedFiles].filter((file) => API_DOC_PATTERN.test(file));
  const architectureLawChanges = [...changedFiles].filter((file) =>
    ARCHITECTURE_LAW_PATTERNS.some((pattern) => pattern.test(file)),
  );
  const authMessageAuditTriggers = [...changedFiles].filter((file) =>
    AUTH_MESSAGE_AUDIT_TRIGGERS.some((pattern) => pattern.test(file)),
  );

  return {
    changedEntries,
    changedFiles,
    event,
    prBody,
    protectedChanges,
    routeFilesChanged,
    apiDocsChanged,
    architectureLawChanges,
    authMessageAuditTriggers,
    likelyMajorModule: isLikelyMajorModuleWork(changedEntries),
    migrationChanged: hasMigrationChange(changedEntries),
    qualityExceptionsTouched: changedFiles.has(QUALITY_EXCEPTIONS_FILE),
    changelogTouched: changedFiles.has(CHANGELOG_FILE),
  };
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

function checkRouteDocCoupling(context) {
  const failures = [];
  const { changedFiles, routeFilesChanged, apiDocsChanged } = context;

  for (const routeFile of routeFilesChanged) {
    const requiredDoc = ROUTE_DOC_COUPLING.get(routeFile);

    if (requiredDoc && !changedFiles.has(requiredDoc)) {
      failures.push(
        `Changed route file ${routeFile} requires a same-PR API-doc update to ${requiredDoc}.`,
      );
      continue;
    }

    if (!requiredDoc && apiDocsChanged.length === 0) {
      failures.push(
        `Changed route file ${routeFile} requires a same-PR backend/docs/api/*.md update so route-to-doc coupling stays explicit.`,
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

function checkCpBoundaries() {
  const failures = [];
  const cpFiles = walkCodeFiles(abs('cp/src'));

  for (const file of cpFiles) {
    const relFile = toRepoPath(file);
    const content = fs.readFileSync(file, 'utf8');

    // Block cp/src/ from importing anything inside frontend/src/.
    for (const pattern of CP_FRONTEND_IMPORT_PATTERNS) {
      if (pattern.regex.test(content)) {
        failures.push(
          `CP boundary violation: ${relFile} must not ${pattern.label}. CP and the tenant frontend are separate packages.`,
        );
      }
    }

    // Block cp/src/ from referencing the backend origin directly.
    // The two intentional infrastructure files (ssr-api-client + api proxy route)
    // are allowlisted — they are the CP equivalents of the frontend proxy files.
    if (!CP_PRIVATE_BACKEND_ALLOWLIST.has(relFile)) {
      for (const pattern of CP_PRIVATE_BACKEND_PATTERNS) {
        if (pattern.regex.test(content)) {
          failures.push(
            `CP same-origin violation: ${relFile} must not reference ${pattern.label}. CP API calls must go through the proxy or CP-scoped routes.`,
          );
        }
      }
    }
  }

  return failures;
}

function checkLinkedUpdateContext(context) {
  const failures = [];
  const warnings = [];
  const { protectedChanges, prBody, event } = context;

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

function checkArchitectureLawLinkage(context) {
  const failures = [];
  const warnings = [];
  const { architectureLawChanges, event, prBody, changedFiles } = context;

  if (architectureLawChanges.length === 0) {
    return { failures, warnings };
  }

  if (!isPullRequestEvent(event)) {
    warnings.push(
      `ADR / architecture-law linkage validation skipped outside pull_request event for: ${architectureLawChanges.join(', ')}.`,
    );
    return { failures, warnings };
  }

  if (!prBody) {
    failures.push(
      `Architecture-law-sensitive files changed (${architectureLawChanges.join(', ')}), but PR body is missing.`,
    );
    return { failures, warnings };
  }

  const linkageSection = extractMarkdownSection(prBody, 'ADR / architecture-law linkage');

  if (!linkageSection || isBlankOrNotApplicable(linkageSection)) {
    failures.push(
      `Architecture-law-sensitive files changed (${architectureLawChanges.join(', ')}), but the PR body does not contain a filled “ADR / architecture-law linkage” section.`,
    );
  }

  const checkedCount = countCheckedLabels(linkageSection, ADR_LINKAGE_LABELS);
  if (checkedCount === 0) {
    failures.push('ADR / architecture-law linkage section exists, but no option is checked.');
  } else if (checkedCount > 1) {
    failures.push('ADR / architecture-law linkage section must have exactly one checked option.');
  }

  const adrUpdated = isCheckedLabel(linkageSection, 'ADR updated in this PR');
  const adrAdded = isCheckedLabel(linkageSection, 'New ADR added in this PR');
  const decisionLogUpdated = isCheckedLabel(linkageSection, 'Decision log updated in this PR');
  const noAdrRequired = isCheckedLabel(linkageSection, 'No ADR or decision-log update required');

  const adrFilesChanged = [...changedFiles].some((file) => ADR_FILE_PATTERN.test(file));
  const decisionLogChanged = changedFiles.has(DECISION_LOG_FILE);

  if ((adrUpdated || adrAdded) && !adrFilesChanged) {
    failures.push(
      'ADR / architecture-law linkage claims an ADR update, but no backend/docs/adr/*.md file changed in this PR.',
    );
  }

  if (decisionLogUpdated && !decisionLogChanged) {
    failures.push(
      'ADR / architecture-law linkage claims a decision-log update, but docs/decision-log.md was not changed in this PR.',
    );
  }

  if (noAdrRequired) {
    const narrative = extractNarrativeText(linkageSection);
    if (!narrative || /^not applicable\.?$/i.test(narrative)) {
      failures.push(
        'ADR / architecture-law linkage is marked “No ADR or decision-log update required”, but no explanation was provided.',
      );
    }
  }

  return { failures, warnings };
}

function checkModuleQualityGate(context) {
  const failures = [];
  const warnings = [];
  const { prBody, event, likelyMajorModule, qualityExceptionsTouched } = context;

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

  const applicabilitySection = extractMarkdownSection(prBody, 'Applicability');
  if (!applicabilitySection) {
    failures.push('PR body is missing the “Applicability” section inside Module Quality Gate.');
    return { failures, warnings };
  }

  const applicabilityCheckedCount = countCheckedLabels(
    applicabilitySection,
    MODULE_APPLICABILITY_LABELS,
  );
  if (applicabilityCheckedCount === 0) {
    failures.push(
      'Applicability section exists, but neither “Applicable” nor “Not applicable” is checked.',
    );
  } else if (applicabilityCheckedCount > 1) {
    failures.push(
      'Applicability section cannot have both “Applicable” and “Not applicable” checked.',
    );
  }

  const applicableChecked = isCheckedLabel(
    applicabilitySection,
    'Applicable — this PR introduces or substantially expands a major module',
  );
  const notApplicableChecked = isCheckedLabel(
    applicabilitySection,
    'Not applicable — this PR does not introduce or substantially expand a major module',
  );

  if (likelyMajorModule && !applicableChecked) {
    failures.push(
      'This PR looks like likely major-module or major-surface work, but the Module Quality Gate is not marked as applicable.',
    );
  }

  if (notApplicableChecked) {
    const narrative = extractNarrativeText(applicabilitySection);
    if (!narrative) {
      failures.push(
        'Module Quality Gate is marked “Not applicable”, but no short reason was provided.',
      );
    }
  }

  if (!applicableChecked) {
    if (qualityExceptionsTouched) {
      failures.push(
        `This PR changes ${QUALITY_EXCEPTIONS_FILE}, but Module Quality Gate is not marked as applicable.`,
      );
    }
    return { failures, warnings };
  }

  const mandatoryGatesSection = extractMarkdownSection(prBody, 'Mandatory gates');
  if (!mandatoryGatesSection || isBlankOrNotApplicable(mandatoryGatesSection)) {
    failures.push(
      'Module Quality Gate is applicable, but the “Mandatory gates” section is missing or blank.',
    );
  }

  if (
    mandatoryGatesSection &&
    !isCheckedLabel(
      mandatoryGatesSection,
      'Track A signoff requested from Lead Architect or Designated Quality Owner',
    )
  ) {
    failures.push(
      'Module Quality Gate is applicable, but “Track A signoff requested from Lead Architect or Designated Quality Owner” is not checked.',
    );
  }

  const evidenceSection = extractMarkdownSection(prBody, 'Evidence / links');
  if (!evidenceSection || isBlankOrNotApplicable(evidenceSection)) {
    failures.push(
      'Module Quality Gate is applicable, but the “Evidence / links” section is blank or marked not applicable.',
    );
  }

  const signoffEvidenceSection = extractMarkdownSection(prBody, 'Track A signoff evidence');
  if (!signoffEvidenceSection || isBlankOrNotApplicable(signoffEvidenceSection)) {
    failures.push(
      'Module Quality Gate is applicable, but the “Track A signoff evidence” section is blank or marked not applicable.',
    );
  } else if (/pending owner signoff\.?/i.test(signoffEvidenceSection)) {
    warnings.push('Track A signoff evidence is still marked as pending owner signoff.');
  }

  const deferredQualityTargetsSection = extractMarkdownSection(prBody, 'Deferred quality targets');
  if (!deferredQualityTargetsSection || isBlank(deferredQualityTargetsSection)) {
    failures.push(
      'Module Quality Gate is applicable, but the “Deferred quality targets” section is blank.',
    );
  }

  const qualityExceptionRecordSection = extractMarkdownSection(prBody, 'Quality exception record');
  if (!qualityExceptionRecordSection || isBlank(qualityExceptionRecordSection)) {
    failures.push(
      'Module Quality Gate is applicable, but the “Quality exception record” section is blank.',
    );
  }

  if (qualityExceptionsTouched && isBlankOrNotApplicable(qualityExceptionRecordSection)) {
    failures.push(
      `This PR changes ${QUALITY_EXCEPTIONS_FILE}, but the “Quality exception record” section is blank or marked not applicable.`,
    );
  }

  const refusalNotesSection = extractMarkdownSection(prBody, 'Refusal / escalation notes');
  if (!refusalNotesSection || isBlank(refusalNotesSection)) {
    failures.push(
      'Module Quality Gate is applicable, but the “Refusal / escalation notes” section is blank.',
    );
  }

  if (
    refusalNotesSection &&
    !isBlankOrNotApplicable(refusalNotesSection) &&
    !qualityExceptionsTouched
  ) {
    failures.push(
      `Refusal / escalation notes were provided, but ${QUALITY_EXCEPTIONS_FILE} was not updated in this PR.`,
    );
  }

  return { failures, warnings };
}

function checkReleaseManagement(context) {
  const failures = [];
  const warnings = [];
  const { prBody, event, migrationChanged, changelogTouched } = context;

  if (!isPullRequestEvent(event)) {
    warnings.push('Release / Change Management validation skipped: Not a PR event.');
    return { failures, warnings };
  }

  if (!prBody) {
    failures.push(
      'PR body is empty. The Release / Change Management section must be present in the PR description.',
    );
    return { failures, warnings };
  }

  const releaseManagementSection = extractMarkdownSection(prBody, 'Release / Change Management');
  if (!releaseManagementSection) {
    failures.push('PR body is missing the “Release / Change Management” section.');
    return { failures, warnings };
  }

  const releaseLaneSection = extractMarkdownSection(prBody, 'Release lane');
  let checkedLaneCount = 0;

  if (!releaseLaneSection) {
    failures.push('PR body is missing the “Release lane” section.');
  } else {
    checkedLaneCount = countCheckedLabels(releaseLaneSection, RELEASE_LANE_LABELS);
    if (checkedLaneCount === 0) {
      failures.push('Release lane section exists, but no lane is checked.');
    } else if (checkedLaneCount > 1) {
      failures.push('Release lane section must have exactly one checked lane.');
    }
  }

  const laneBChecked = isCheckedLabel(
    releaseLaneSection,
    'Lane B — topology / auth / security-sensitive change',
  );
  const laneCChecked = isCheckedLabel(releaseLaneSection, 'Lane C — migration-bearing change');
  const laneDChecked = isCheckedLabel(releaseLaneSection, 'Lane D — hotfix');

  const rollbackSection = extractMarkdownSection(prBody, 'Rollback expectation');
  if (!rollbackSection || isBlank(rollbackSection)) {
    failures.push('PR body is missing a filled “Rollback expectation” section.');
  }

  const verificationSection = extractMarkdownSection(prBody, 'Post-change verification');
  if (!verificationSection || isBlank(verificationSection)) {
    failures.push('PR body is missing a filled “Post-change verification” section.');
  }

  const releaseNotesSection = extractMarkdownSection(prBody, 'Deployment / release notes');
  if (!releaseNotesSection || isBlank(releaseNotesSection)) {
    failures.push('PR body is missing a filled “Deployment / release notes” section.');
  }

  const changelogSection = extractMarkdownSection(prBody, 'Changelog impact');
  if (!changelogSection || isBlank(changelogSection)) {
    failures.push('PR body is missing a filled “Changelog impact” section.');
  } else {
    const checkedChangelogCount = countCheckedLabels(changelogSection, CHANGELOG_IMPACT_LABELS);

    if (checkedChangelogCount === 0) {
      failures.push('Changelog impact section exists, but no changelog disposition is checked.');
    } else if (checkedChangelogCount > 1) {
      failures.push('Changelog impact section must have exactly one checked disposition.');
    }

    const changelogUpdatedChecked = isCheckedLabel(
      changelogSection,
      'CHANGELOG.md updated in this PR',
    );
    const noChangelogChecked = isCheckedLabel(changelogSection, 'No changelog entry required');

    if (changelogUpdatedChecked && !changelogTouched) {
      failures.push(
        `Changelog impact claims "${CHANGELOG_FILE} updated in this PR", but ${CHANGELOG_FILE} was not changed in this PR.`,
      );
    }

    if (noChangelogChecked) {
      const narrative = extractNarrativeText(changelogSection);
      if (!narrative) {
        failures.push(
          'Changelog impact is marked “No changelog entry required”, but no explanation was provided.',
        );
      }

      if ((laneBChecked || laneCChecked || laneDChecked) && !narrative) {
        failures.push(
          'Lane B, Lane C, and Lane D changes require an explicit reviewer-visible reason when no changelog entry is required.',
        );
      }
    }
  }

  const migrationSection = extractMarkdownSection(prBody, 'Migration safety');

  if (migrationChanged && !laneCChecked) {
    failures.push(
      'This PR changes migration files, but “Lane C — migration-bearing change” is not checked.',
    );
  }

  if (migrationChanged) {
    if (!migrationSection || isBlankOrNotApplicable(migrationSection)) {
      failures.push(
        'This PR changes migration files, but the “Migration safety” section is blank or marked not applicable.',
      );
    }
  } else if (laneCChecked && (!migrationSection || isBlankOrNotApplicable(migrationSection))) {
    failures.push(
      'Release lane is marked as Lane C, but the “Migration safety” section is blank or marked not applicable.',
    );
  }

  const hotfixDetailsSection = extractMarkdownSection(prBody, 'Hotfix details');
  if (laneDChecked) {
    if (!hotfixDetailsSection || isBlankOrNotApplicable(hotfixDetailsSection)) {
      failures.push(
        'Release lane is marked as Lane D — hotfix, but the “Hotfix details” section is blank or marked not applicable.',
      );
    }
  }

  if (checkedLaneCount === 1 && !laneDChecked) {
    if (hotfixDetailsSection && !isBlankOrNotApplicable(hotfixDetailsSection)) {
      warnings.push(
        'Hotfix details were provided even though the release lane is not marked as Lane D — hotfix.',
      );
    }
  }

  return { failures, warnings };
}

function checkSelectiveErrorMessageAudit(context) {
  const failures = [];
  const { authMessageAuditTriggers, changedFiles } = context;

  if (authMessageAuditTriggers.length === 0) {
    return failures;
  }

  if (!changedFiles.has(AUTH_MESSAGE_AUDIT_FILE)) {
    failures.push(
      `User-visible auth/invite message surfaces changed (${authMessageAuditTriggers.join(', ')}), but ${AUTH_MESSAGE_AUDIT_FILE} was not updated in the same PR.`,
    );
  }

  return failures;
}

function isLikelyMajorModuleWork(changedEntries) {
  const backendModuleTouchCount = new Map();
  const frontendSurfaceTouchCount = new Map();

  for (const entry of changedEntries) {
    const backendModuleMatch = entry.path.match(/^backend\/src\/modules\/([^/]+)\//);
    if (backendModuleMatch) {
      const moduleName = backendModuleMatch[1];
      backendModuleTouchCount.set(moduleName, (backendModuleTouchCount.get(moduleName) ?? 0) + 1);
    }

    const frontendSurfaceMatch = entry.path.match(/^frontend\/src\/app\/([^/]+)\//);
    if (frontendSurfaceMatch) {
      const surfaceName = frontendSurfaceMatch[1];
      frontendSurfaceTouchCount.set(
        surfaceName,
        (frontendSurfaceTouchCount.get(surfaceName) ?? 0) + 1,
      );
    }

    if (entry.status !== 'D' && /^backend\/docs\/api\/[^/]+\.md$/.test(entry.path)) {
      return true;
    }

    if (
      entry.status !== 'D' &&
      /^backend\/src\/shared\/db\/migrations\/[^/]+\.ts$/.test(entry.path)
    ) {
      return true;
    }

    if (entry.status !== 'D' && /^frontend\/src\/features\/[^/]+\//.test(entry.path)) {
      return true;
    }

    if (entry.status !== 'D' && /^frontend\/src\/app\/[^/]+\/page\.tsx$/.test(entry.path)) {
      return true;
    }

    if (
      entry.status !== 'D' &&
      /^backend\/src\/modules\/[^/]+\//.test(entry.path) &&
      entry.status !== 'M'
    ) {
      return true;
    }
  }

  for (const count of backendModuleTouchCount.values()) {
    if (count >= 5) {
      return true;
    }
  }

  for (const count of frontendSurfaceTouchCount.values()) {
    if (count >= 4) {
      return true;
    }
  }

  return false;
}

function hasMigrationChange(changedEntries) {
  return changedEntries.some((entry) =>
    MIGRATION_PATH_PATTERNS.some((pattern) => pattern.test(entry.path)),
  );
}

function writeSummary(context, failures, warnings) {
  const lines = [
    '## Repo guard summary',
    '',
    `- Changed files: ${context.changedEntries.length}`,
    `- Protected law/governance files changed: ${formatList(context.protectedChanges)}`,
    `- Route files changed: ${formatList(context.routeFilesChanged)}`,
    `- API docs changed: ${formatList(context.apiDocsChanged)}`,
    `- Architecture-law-sensitive changes: ${formatList(context.architectureLawChanges)}`,
    `- Likely major-module / major-surface work: ${context.likelyMajorModule ? 'yes' : 'no'}`,
    `- Migration-bearing change detected: ${context.migrationChanged ? 'yes' : 'no'}`,
    `- Quality exception register changed: ${context.qualityExceptionsTouched ? 'yes' : 'no'}`,
    `- Changelog changed: ${context.changelogTouched ? 'yes' : 'no'}`,
    `- Auth/invite message-audit trigger files changed: ${formatList(context.authMessageAuditTriggers)}`,
    '',
    `- Failures: ${failures.length}`,
    `- Warnings: ${warnings.length}`,
  ];

  if (failures.length > 0) {
    lines.push('', '### Failures', '', ...failures.map((failure) => `- ${failure}`));
  }

  if (warnings.length > 0) {
    lines.push('', '### Warnings', '', ...warnings.map((warning) => `- ${warning}`));
  }

  const summary = `${lines.join('\n')}\n`;

  console.log(`\n${summary}`);

  const stepSummaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (stepSummaryPath) {
    try {
      fs.appendFileSync(stepSummaryPath, `${summary}\n`);
    } catch {
      // Best-effort summary only.
    }
  }
}

function countCheckedLabels(section, labels) {
  let count = 0;
  for (const label of labels) {
    if (isCheckedLabel(section, label)) {
      count += 1;
    }
  }
  return count;
}

function isCheckedLabel(section, label) {
  if (!section) {
    return false;
  }

  const regex = new RegExp(`- \\[([xX])\\] ${escapeRegExp(label)}`, 'm');
  return regex.test(section);
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
  if (!markdown) {
    return '';
  }

  const headings = [...markdown.matchAll(/^(#{1,6})\s+(.+?)\s*$/gm)].map((match) => ({
    level: match[1].length,
    text: match[2].trim(),
    index: match.index ?? 0,
    raw: match[0],
  }));

  const currentIndex = headings.findIndex((heading) => heading.text === headingText);
  if (currentIndex === -1) {
    return '';
  }

  const current = headings[currentIndex];
  const start = current.index + current.raw.length;

  let end = markdown.length;
  for (let index = currentIndex + 1; index < headings.length; index += 1) {
    const next = headings[index];
    if (next.level <= current.level) {
      end = next.index;
      break;
    }
  }

  return markdown.slice(start, end).trim();
}

function extractNarrativeText(section) {
  if (!section) {
    return '';
  }

  return section
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !line.startsWith('- ['))
    .filter((line) => !line.startsWith('<!--'))
    .filter((line) => !/^if\b/i.test(line))
    .join('\n')
    .trim();
}

function isBlankOrNotApplicable(value) {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.length === 0 || normalized === 'not applicable.' || normalized === 'not applicable'
  );
}

function isBlank(value) {
  return value.trim().length === 0;
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

function formatList(values) {
  if (!values || values.length === 0) {
    return 'none';
  }

  return values.join(', ');
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
