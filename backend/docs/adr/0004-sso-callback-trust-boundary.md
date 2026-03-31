# ADR 0004 — SSO Callback Trust Boundary

## Status

Accepted

## Date

2026-03-31

## Owners

Lead Architect / Designated Quality Owner

---

## Context

The repository already implements Google and Microsoft SSO flows under the locked Hubins topology:

- browser starts SSO by full-page navigation to same-origin `/api/auth/sso/:provider`
- backend sets a short-lived encrypted `sso-state` cookie
- OAuth provider redirects back to `/api/auth/sso/:provider/callback`
- backend validates state, resolves user/membership/tenant, creates session, clears state cookie, and redirects into backend-authoritative continuation flow

This callback path is one of the highest-risk trust boundaries in the repo because it combines:

- cross-site navigation back from an external identity provider
- tenant identity derived from host
- a separate short-lived cookie with `SameSite=Lax`
- redirect / return-path handling
- session creation and post-auth continuation routing

Without an explicit ADR, it is too easy for future refactors to weaken one of the boundary checks while keeping the happy path green.

---

## Decision

The SSO callback trust boundary is governed by the following rules.

## 1. The callback trusts host-derived tenant identity, not query/body tenant hints

The callback request is bound to the tenant identified from the incoming request host.
No tenant identifier from query params, request body, or frontend route state may override that host-derived tenant.

This rule is consistent with the broader platform topology and tenant-isolation model.

## 2. The callback requires both the state query param and the matching `sso-state` cookie

The callback is invalid unless all of the following are true:

- the `state` query parameter exists
- the `sso-state` cookie exists
- the cookie value exactly matches the `state` query param value

If any of these conditions fail, the callback fails closed with a validation error.

This prevents accepting a provider redirect that is not bound to the browser flow that initiated SSO.

## 3. The state payload must decrypt successfully under the configured SSO-state key

The callback only proceeds if the encrypted state can be decrypted and parsed with the active SSO-state encryption key.

If decryption fails, the callback fails closed.

No best-effort or partial recovery path is allowed.

## 4. The decrypted state must remain coherent with the live callback request

The callback only proceeds if the decrypted state remains coherent with the callback request, including at minimum:

- tenant identity derived from host
- provider path being handled
- expected return-path / redirect constraints

A state created on tenant A must not validate on tenant B.
A state created for one provider must not be accepted on another provider callback path.

## 5. Return-path handling is validated twice, not assumed safe after start

Return-path / redirect intentions are validated when SSO is initiated and validated again at callback/consumption time.

The frontend may use `nextAction` or route hints for UX continuity, but backend session truth remains authoritative.

The callback must never trust a client-controlled return path without server-side validation.

## 6. Session creation happens only after successful callback validation

The existence of a valid provider redirect alone is not enough.
A backend session is created only after the callback boundary has passed all validation checks and the membership/user outcome is accepted by platform rules.

## 7. The state cookie is not the session cookie and must remain operationally separate

The `sso-state` cookie and the session cookie are distinct security objects with different purposes and different SameSite rules.

- session cookie: authenticated server-side session identity, `SameSite=Strict`
- SSO state cookie: short-lived callback correlation material, `SameSite=Lax`

They must not be merged, reused, or generalized into one cookie abstraction.

## 8. The state cookie is cleared when the callback completes

After successful callback processing, the `sso-state` cookie is cleared.
This reduces replay surface and keeps the callback state strictly short-lived.

## 9. The current baseline does not require a server-side used-state ledger

The current accepted baseline relies on:

- encrypted short-lived state
- exact cookie/query equality
- host/provider coherence checks
- backend validation of return-path rules
- immediate cookie clearing on success
- provider-side authorization code single-use semantics

The repository does **not** currently introduce a server-side used-state ledger for callback state.
This is an intentional Stage 4 baseline decision, not an accidental omission.

If future threat posture, provider behavior, or incident history suggests stronger replay controls are needed, that must be handled by a new ADR rather than quiet drift.

---

## Consequences

### Positive

- the highest-risk callback boundary is now explicit and durable
- future SSO refactors have a concrete security contract to preserve
- abuse regressions can map directly to named boundary rules
- topology and session-authority rules remain consistent across password and SSO login flows

### Costs / tradeoffs

- callback logic remains stricter and less forgiving to malformed traffic
- SSO state key rotation invalidates in-flight starts
- no used-state ledger means replay resistance depends on the current layered design rather than a server-side consumed-state store

### What must remain true in code and tests

The following must remain coupled:

- callback validation code
- cookie contract
- state encryption/decryption code
- return-path validation
- session creation timing
- SSO abuse regression tests

---

## Alternatives considered

## A. Trust only the query `state` and skip cookie correlation

Rejected.
This weakens CSRF/callback correlation and makes cross-flow tampering easier.

## B. Allow tenant selection from query or frontend state during callback

Rejected.
This violates the repo's host-derived tenant model and materially weakens tenant isolation.

## C. Treat frontend redirect hints as authoritative after callback

Rejected.
Backend session truth and `nextAction` resolution remain authoritative.
Frontend hints are not trusted security inputs.

## D. Add a server-side used-state ledger now

Deferred, not adopted in this ADR.
The current repo baseline does not require it yet, and adding it would introduce more stateful coordination and storage behavior.
If adopted later, it should be justified explicitly and implemented through a follow-up ADR.

---

## Operational notes

- rotating `SSO_STATE_ENCRYPTION_KEY` invalidates in-flight SSO starts that have not yet completed callback
- that effect is acceptable because the cookie is intentionally short-lived
- operators should rotate this key during a low-traffic window and expect some active SSO starts to retry
- any change to callback error wording, cookie names, SameSite behavior, or state-validation branching requires test review

---

## Links

- `docs/security-model.md`
- `docs/security/threat-model.md`
- `backend/test/unit/auth/sso/sso-state-validate.spec.ts`
- `backend/test/e2e/auth-sso-state-abuse.spec.ts`
- `frontend/test/unit/shared/auth/sso.spec.ts`
- `frontend/test/unit/shared/auth/redirects.spec.ts`
- `frontend/test/unit/shared/auth/url-tokens.spec.ts`
