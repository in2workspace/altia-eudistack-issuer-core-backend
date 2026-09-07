# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Tech Debt — Atomic reactive writes for status list creation (`BitstringStatusListProvider`, H-02 / H-07)**: refactored `BitstringStatusListProvider.createNewList` to execute `save` (TX1) and `updateSignedCredential` (TX2) in short reactive transactions via `TransactionalOperator`, keeping the external HTTP/QTSP signing call outside of any transactional boundary, with a transactionally wrapped compensation delete on failure. Conforms to the module transactional policy (`persistence-layer-rules.md`, `reactive-code-analysis.md`).
- **Tech Debt (EUDISTACK-650) — Decouple `Issuance` persistence from the domain (H-05)**: `Issuance` no longer carries `@Table`/`@Column`/`@Version`/auditing annotations, and `IssuanceServiceImpl` no longer injects `R2dbcEntityTemplate` directly — same pattern already used by the `apiclient` bounded context (port + infrastructure entity + mapper). Added `IssuancePort` (domain), `IssuanceEntity` + `IssuanceMapper` + `IssuanceR2dbcRepository` + `IssuanceR2dbcAdapter` (infrastructure); `CredentialExpirationScheduler` and the Testcontainers ITs that seed `issuance` rows directly now depend on `IssuancePort` instead of the old Spring Data repository. Added an ArchUnit rule (`domainShouldNotDependOnSpringData`) blocking `..domain..` → `org.springframework.data..` going forward, with a documented, narrow exemption for the pre-existing `Tenant*` entities and `TenantCredentialProfileServiceImpl` (same debt, out of this ticket's scope). No behavior change: optimistic-locking `version` and auditing fields round-trip through the mapper exactly as before.
  - **Follow-up (code review, same ticket): closed the remaining `org.springframework.dao` leak.** `IssuanceR2dbcAdapter.insert`/`save` now map `OptimisticLockingFailureException` to the domain's `ConcurrentIssuanceUpdateException` at the infrastructure boundary, so `IssuanceServiceImpl` and `CredentialExpirationScheduler` no longer import a Spring Data-access type — `domainShouldNotDependOnSpringData` now also blocks `org.springframework.dao..`. Testcontainers seed helpers (`BitstringStatusListControllerRevokeIT`, `RevocationInstructionListenerIT`, `RevocationInstructionSingleTenantIT`) switched from `issuancePort.save` to `issuancePort.insert` to match production's `saveIssuance` path, and `IssuanceR2dbcAdapterTest` now asserts `insert`/`save` are mutually exclusive and covers the new exception mapping. No behavior change.

### Added

- **`value_map` now propagates through `/.well-known/openid-credential-issuer`**: `CredentialProfile.ClaimDefinition` didn't declare a `value_map` field, so Jackson silently dropped it when deserializing credential profiles even though the source profile JSON already carried it (e.g. `gx.labelcredential.w3c.2`'s `gx:labelLevel` claim). The issuer metadata endpoint now serves it unchanged, letting clients map raw enum values (`P`) to their display label (`Professional`) without needing a separate, locally-bundled copy of the schema.

- **EUD-225 — Automatic credential revocation from a message-queue instruction (FR-11)**: an external client system can now publish a revocation instruction to a RabbitMQ queue and have the Issuer apply it with the exact same domain effect as an operator-initiated revocation (status change, status list publication, audit trail) — no human in the loop. Disabled by default (`issuer.messaging.revocation.enabled=false`, AD-6): a deployment with this Story merged behaves identically to before unless explicitly opted in.
  - `RevocationInstructionListener` (`@RabbitListener`, gated by the property above): validates the message at the border, resolves the effective tenant (`RevocationTenantBinding`, AD-8), writes the tenant into the Reactor `Context` before touching any repository, and bridges into the reactive pipeline with a bounded `block(30s)` confined to the AMQP container's own thread pool.
  - `HandleRevocationInstructionWorkflow` orchestrates message-level idempotency (`RevocationInstructionInbox`, a `revocation_instruction_inbox` table per tenant schema with an atomic `claim`/`release`/`markProcessed`/`markSkipped`) around the existing `RevocationWorkflow.revokeSystem`, translating "credential no longer revocable" into a silent no-op with its own audit trail rather than an error.
  - **AD-8 — single-tenant deployment mode**: `issuer.messaging.revocation.tenant-binding` lets a dedicated on-premise deployment declare its own tenant, so an instruction without a `tenantId` field is attributed to it; a discordant `tenantId` is rejected (`TenantBindingMismatchException`) rather than silently trusted. The default (empty) behavior — `tenantId` mandatory in the message, never inferred — is unchanged and covered by regression tests.
  - **AD-1 — the operator's caller token is no longer required for system-triggered revocation**: `RevocationWorkflow.revokeSystem` drops the vestigial `bearerToken` parameter (never used to authorize or sign in that path) and takes an explicit `actor` instead of resolving "unknown" from a non-existent security context (AD-3) — this also fixes the OID4VCI `credential_deleted` notification path's audit trail, which previously recorded `unknown`.
  - **AD-2 — re-signing a status list without an HTTP request behind it**: `PersistedStatusListPublicBaseUrlResolver` derives the public issuer base URL a status list was originally signed against directly from the persisted, already-signed list (fail-closed if it cannot), preserving the W3C Bitstring Status List / IETF Token Status List `id`/`sub` ↔ dereference-URL correspondence for system-triggered revocations.
  - Malformed payloads, unknown tenants, non-existent credentials and exhausted retries route to a dead-letter queue (`eudistack.revocation.instructions.dlq`) without blocking subsequent messages; a transient dependency failure (QTSP, database) retries with backoff (1s→2s→4s) and recovers within the configured attempts.
  - First messaging dependency of the platform (`spring-boot-starter-amqp`, Testcontainers RabbitMQ for integration tests) — see `docs/EUD-6-revocar-credencial/EUD-225/spec-deltas.md` SD-01/SD-02/SD-03 for the NFR thresholds, estimation and STG/PROD broker-provisioning deltas raised against the locked SRS.
  - **Fixed a pre-existing concurrency gap in `issuance` (SD-04)**, found while integration-testing the operator-vs-queue revocation race (ES-03): `Issuance` had no version column, so `IssuanceServiceImpl.updateIssuanceStatusToRevoked` (and 6 other `issuanceRepository.save()` call sites) could lose a lost-update race under real concurrency. Added a `version` column (`V11`, Spring Data R2DBC native optimistic locking); `updateIssuanceStatusToRevoked` now reconciles a lost race against an already-`REVOKED` row into the same no-op both revocation paths already handle (`InvalidCredentialStatusTransitionException`); the other 6 write sites translate the conflict into a new `ConcurrentIssuanceUpdateException` with a clear log line instead of a bare R2DBC exception. See `docs/EUD-6-revocar-credencial/EUD-225/spec-deltas.md` SD-04 for the full detail.
  - **`/verify` + `/code-review` remediation** (commit-hygiene rebase of the AD-1/AD-3 sequence; audit/log sanitization hardened against forged log lines and forged `key=value` fields, `declaredTenant` constrained to a fixed charset with a SHA-256 fallback; environment-suffix stripping fixed to never touch the tenant-binding mismatch comparison itself; `messageId`/`tenantId`/`reason` bounded at the message border; TLS required for the broker connection with an explicit local-dev escape hatch; RabbitMQ credentials can no longer be a literal `guest`; DLQ headers no longer carry raw exception detail; jittered retry backoff; a `revocation.instruction.processed{tenant,actor,outcome}` counter as the basis for AD-7's still-pending volume-anomaly alert) — see the commit history on `feature/EUD-225-revocacion-por-cola-de-mensajes` for the itemized findings (F1–F17, B-EC06, W1/W2).
  - **CI: fixed the SonarCloud Reliability Rating gate (rule `java:S8745`)**: `RevocationInstructionListenerIT` and `RevocationInstructionSingleTenantIT` each declared their setup across multiple `@BeforeEach`-annotated methods, whose relative execution order JUnit 5 does not guarantee within a single class. Consolidated each into one `@BeforeEach` calling the (now private) setup steps in an explicit, documented order — no behavioral change, both classes pass unchanged.
  - **R1 (targeted re-verification, found after the pass above): `auditAttempted` had its own residual of the same forged-field vulnerability** — it wrapped `formatDetails()`'s output in a second, literal `details="{}"` quoting layer that didn't compose with `formatValue`'s own escaping, so a value needing its own quotes closed the outer one early and leaked as bare top-level fields. `auditSuccess`/`auditFailure` never had this second layer; `auditAttempted` now matches them exactly. Deployment-hardening items from the same re-verification pass (broker TLS certificate validation depth, the `allow-insecure-transport` escape hatch also weakening the `guest` credential rejection, DLQ queue bounds, revocation-counter tag cardinality on the failure path) are deliberately deferred — see `docs/EUD-6-revocar-credencial/EUD-225/tech-debt.md` TD-4..TD-8 — because this integration is not provisioned for any client today (`enabled=false`, nothing in `eudistack-platform-iac`) and is meant to demonstrate the capability for tender purposes; the broker-hardening work is scoped to whenever a real customer integration is undertaken with infra.
  - **PR review findings (GitHub Advanced Security / CodeQL + Copilot code review, found after the PR was opened):**
    - **Log injection (`java/log-injection`, 3 instances) in `RevocationWorkflow.revokeInternal`**: `issuanceId` reached several `log.info`/`log.debug` statements unsanitized. It is already boundary-validated as a well-formed UUID on the queue path (`RevocationInstructionMessageMapper`), but the operator HTTP path's `RevokeCredentialRequest.issuanceId` only had `@NotBlank` — no format constraint — so a crafted value (e.g. containing a newline) could forge a fake log line via that path. Added a `@Pattern` UUID-format constraint to `RevokeCredentialRequest` (closing the gap at the boundary, matching what the queue path already enforces and what the `Issuance.issuanceId` column type actually is) and, defense-in-depth, quote/escape the value for every log statement in `revokeInternal` — the raw value is kept for the actual lookup/audit calls, which need the exact identifier. New `RevocationAuditDetails.quoteIfNeeded` (quotes and escapes an embedded `=`/`"`, on top of `sanitize`'s control-character stripping) — plain `sanitize` alone does not stop a value from forging extra `key=value` fields in a non-audit log line the way `AuditServiceImpl.formatValue` already does for the AUDIT sink; CodeQL's continued flagging on this exact call site after an initial `sanitize`-only fix is what surfaced the distinction.
    - **Potential infinite reclaim loop (Copilot, HIGH) in `R2dbcRevocationInstructionInbox.resolveExistingClaim`**: the Java-side freshness check (`claimedAt.isAfter(leaseThreshold)`) and the SQL reclaim condition (`claimed_at < :leaseThreshold`) disagreed at the exact boundary — a row with `claimed_at` equal to the threshold was neither "still fresh" nor "reclaimable", so `reclaimExpired` would update 0 rows and recurse back into `resolveExistingClaim`. Changed the Java-side check to `!claimedAt.isBefore(leaseThreshold)` so the two conditions are now complementary and mutually exclusive, eliminating the gap.
    - **Silent instruction drop under a real multi-replica race (Copilot, found on re-review) in the same method**: `readStatus`'s `.one()` completes empty (not an error) when zero rows match, reachable if a concurrent `release()` — a sibling replica retrying the same redelivered message, AC-09 — deletes the `IN_PROGRESS` row between this method's failed `INSERT ... ON CONFLICT DO NOTHING` and its own `SELECT`. Before this fix, `claim()` itself would complete empty (no `ClaimResult`, no error), and the caller could treat a dropped revocation instruction as silently handled — exactly the failure NFR-R-02 exists to prevent, and reachable specifically in the multi-replica deployment this Story's idempotency design targets. Fixed by retrying `claim()` from scratch (`switchIfEmpty`) when the read comes back empty: the row being gone is the same precondition a fresh claim already knows how to handle.
    - **Log injection (`java/log-injection`) in `AuditServiceImpl.auditSuccess`/`auditFailure`/`auditAttempted`**: `userId`/`resourceType`/`resourceId`/`reason` were interpolated raw, bypassing the exact same escaping (`formatValue`) already applied to `details` map values one parameter over — a gap CodeQL surfaced on the `auditAttempted` line this PR's R1 fix had just touched, but which existed identically in the two sibling methods. All three now route every named field through `formatValue`, not only the details map.
    - **Unbounded recursion in `claim`/`resolveExistingClaim`/`reclaimExpired` (independent code review, MEDIUM)**: the two recovery cycles (lost-race-on-expired-lease, and the vanished-row fix above) re-enter each other only after losing a race to a concurrent claim/release on the same row — not a tight synchronous loop, since each hop is a fresh async DB round-trip, but formally unbounded and undocumented. Added a bounded attempt counter (`MAX_CLAIM_ATTEMPTS = 5`, checked once at `resolveExistingClaim`'s single fan-in point for both cycles) and a new `RevocationInstructionClaimExhaustedException` (unclassified, so retried at the AMQP level like any other unexpected failure) for the pathological case of repeated collisions on one `messageId`.

- **EUD-220 — SBOM CycloneDX and License Gate**: Added CycloneDX 1.6 SBOM generation (`cyclonedxBom`), CI license compliance gate (`license-gate.yml`), and automated SBOM asset attachment to GitHub Releases. The evaluator is vendored at `.github/scripts/license-gate.mjs` with its own `node --test` suite, which the gate workflow runs before evaluating anything: this repository verifies itself without depending on any other one. Free-text upstream license names resolve through a reviewed SPDX equivalence table instead of piling up as expiring exceptions, and the `CODEOWNERS` rules that protect the policy, the exception register and the evaluator sit at the END of the file, because GitHub applies the last matching pattern.
- **EUD-219 — Removal of GPL-3.0 dependency**: the `io.github.novacrypto:Base58` dependency (GPL-3.0 license) has been removed and replaced with a custom `Base58Codec` implementation.

### Fixed

- **CORS Security**: populated `cors-origins.yaml` with default STG and local origins and updated tests to ensure correct classpath loading.
- **CORS Security**: integrated `CorsOriginsLoader` into production configuration, eliminating wildcard `*` allowed origins in favor of a dynamic allow-list from `cors-origins.yaml`.
- **CORS Security**: added `Api-Version` to the allowed headers white-list.
- **CORS Security**: renamed `CorsConfig` to `CorsFilterConfig` for architectural consistency and strengthened tests to validate origin restrictions.
- **`TenantSchemaFlywayMigrator`**: removed manual `CREATE SCHEMA` execution in favor of Flyway's native schema creation (`createSchemas(true)`) and enhanced SQL safety by using standard JDBC practices for dynamic queries.
- **EUD-215 — `/oid4vci/v1/notification` rejected every spec-conformant call with `400`**: OID4VCI 1.0 FINAL §11.1 names the request fields `notification_id`/`event_description` (snake_case), but `NotificationRequest` had no `@JsonProperty` mapping — Jackson only matched the literal Java field name (`notificationId`), so a conformant request deserialized it as `null`, failing `@NotBlank` validation with `400`. Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-happy-flow` test (`OID4VCI-1FINAL-11.2 EnsureHttpStatusCodeIs2xx`). Went unnoticed because our own Wallet PWA sent the same non-conformant camelCase key this record always expected (companion fix in `eudistack-core-wallet-pwa`). Added `@JsonProperty` for the spec-correct snake_case keys, plus `@JsonAlias` for the old camelCase keys so an un-updated wallet build doesn't suddenly start failing.
- **EUD-215 — the Token Status List (`draft-ietf-oauth-status-list`) `lst` claim used the wrong compression, undecodable by any conformant reader**: `TokenStatusListCredentialFactory.buildUnsigned` reused `encodedList` (the shared bitstring storage format — multibase + base64url + **GZIP**, RFC 1952) as-is for the `lst` claim. §4.1 of the draft mandates "DEFLATE [RFC1951] with the ZLIB [RFC1950] data format" — raw DEFLATE inside the 2-byte zlib header + Adler-32 trailer, which is neither GZIP nor bare RFC 1951. Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-happy-flow` test (`OTSL-6.2 CheckCredentialStatus`: `DataFormatException: incorrect header check`). Now decodes back to the raw bitstring (`BitstringEncoder`) and re-compresses with zlib-framed DEFLATE (`new Deflater(BEST_COMPRESSION)`, i.e. `nowrap=false`) before base64url-encoding — the W3C Bitstring Status List JWT (which does use GZIP) is unaffected, it still reads `encodedList` directly. A first attempt at this fix went to header-less DEFLATE (`nowrap=true`), which reproduced the exact same `incorrect header check` on the reader side; the accompanying test now inflates with the default `Inflater` (zlib) rather than `new Inflater(true)`, which accepted both framings and masked the bug.
- **EUD-215 — both status list endpoints served any list regardless of its format, so a wallet following `status.status_list.uri` got a W3C VC it could not decode**: `/token/v1/credentials/status/{id}` (`application/statuslist+jwt`) and `/w3c/v1/credentials/status/{id}` (`application/vc+jwt`) read the same `status_list` table, and `getSignedStatusListCredential` returned the stored blob without consulting the row's `format`. On STG, `GET /issuer/token/v1/credentials/status/2` answered `200` with a `Content-Type: application/statuslist+jwt` carrying a `BitstringStatusListCredential` (`typ: vc+jwt`) — byte-identical to what the W3C endpoint served for the same id. Caught by `OTSL-6.2 CheckCredentialStatus`. A list is now only reachable through the endpoint matching its own format; a mismatch is a `404` (`StatusListNotFoundException`), never a `200` under the wrong media type.
- **EUD-215 — an issuance whose status list entry was already allocated on a list of another format got a status reference that could not resolve**: `BitstringStatusListProvider.findExistingAllocation` looked the allocation up by `issuance_id` and then built the entry URL from the *requested* format, ignoring the format of the list the index actually sits on — producing a `/token/v1/...` URI pointing at a `bitstring_vc` list. Now verifies the stored list first and fails with the new `StatusListFormatMismatchException` instead of emitting a credential whose status is unresolvable.
- **EUD-215 — `/oid4vci/v1/credential` derived the credential format from the stored issuance row instead of the profile, silently downgrading SD-JWT issuance**: `Oid4VciCredentialWorkflowImpl.enrichAndSign` read `proc.getCredentialFormat()` (falling back to `jwt_vc_json`), but the wallet asks by `credential_configuration_id` and the Credential Issuer Metadata advertises `profile.format()` for it — so the profile is the authority. An offer row written before its profile carried a format, or before that profile moved to `dc+sd-jwt`, kept `credential_format` NULL or `jwt_vc_json` and took the whole chain down the W3C branch: `BITSTRING_VC` for the status list allocation instead of `TOKEN_JWT`, and a W3C `credentialStatus` object instead of `status.status_list` inside an SD-JWT VC. Matches the observed STG state, where the `sandbox` tenant has only `bitstring_vc` lists (ids 1–2, nothing above) despite `eu.europa.ec.eudi.pid.1` being published as `dc+sd-jwt`. The profile now wins, with a `WARN` when the stored row disagrees.
- **EUD-215 — `/oauth/token` rejected a missing/invalid PKCE `code_verifier` with `invalid_request` instead of the `invalid_grant` RFC 7636 §4.6 mandates**: a prior fix (EUD-215, PKCE/DPoP error shape) caught `PkceVerifier`'s and `DpopValidationService`'s `IllegalArgumentException`s in one shared `try/catch` and mapped both to `OAuthTokenException.invalidRequest(...)` — correct for a missing/invalid DPoP proof, but RFC 7636 §4.6 specifically requires `invalid_grant` for a `code_verifier` that fails PKCE verification. Caught by the OIDF conformance suite's `fapi2-security-profile-final-ensure-pkce-code-verifier-required` test (`CheckErrorFromTokenEndpointResponseErrorInvalidGrant`: got `invalid_request`, expected `invalid_grant`). Split `TokenServiceImpl.validateAndBuildAuthCodeToken`'s single combined `try/catch` into two separate ones — PKCE failures now map to `OAuthTokenException.invalidGrant(...)`, DPoP failures keep `invalidRequest(...)`.
- **EUD-215 — `/oauth/par` silently accepted a pushed authorization request that itself carried a `request_uri` parameter**: RFC 9126 §4 defines `request_uri` as the PAR endpoint's own *response* value — it must never be accepted as an *input* of the pushed request. `PushedAuthorizationRequest` had no field for it, so Spring's form binder silently dropped the parameter and `ParServiceImpl` never knew it was present, returning a normal `201` instead of rejecting the request. Caught by the OIDF conformance suite's `fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param` test. Added the field (bound only for detection, never otherwise read) and an explicit check rejecting with `OAuthTokenException.invalidRequest(...)` (`400 invalid_request`) when present, alongside the existing `response_type`/`redirect_uri`/PKCE checks.
- **EUD-215 — `/oauth/token` returned our internal Problem-Details body instead of the RFC 6749 §5.2 `{error, error_description}` shape when PKCE or DPoP validation failed on an `authorization_code` grant**: `TokenServiceImpl.validateAndBuildAuthCodeToken` called `PkceVerifier.verifyS256` and `DpopValidationService.validate` directly — both raise plain `IllegalArgumentException` on failure (e.g. `"Missing DPoP proof"`), which `Oidc4vciExceptionHandler`'s generic handler maps to `GlobalErrorMessage` (`{type, title, status, detail, instance}`, no `error` field) instead of `OAuthErrorResponse`. Caught by the OIDF conformance suite's `fapi2-security-profile-final-ensure-holder-of-key-required` test (`CheckTokenEndpointReturnedInvalidRequestGrantOrDPopProofError`: the response was a `400` but had no `error` field to check). Same gap `ParServiceImpl` and `AuthorizationServiceImpl` already had fixed for their own PKCE/DPoP/response_type checks — both calls are now wrapped in a `try/catch` translating `IllegalArgumentException` into `OAuthTokenException.invalidRequest(e.getMessage())` (`400 invalid_request`). PKCE failures had the identical defect (confirmed via a pre-existing unit test that asserted the *wrong*, unwrapped behavior) but no conformance test had caught it yet — fixed alongside DPoP rather than leaving a known-identical gap for a future test to rediscover.
- **EUD-215 — `/oid4vci/v1/authorize` accepted authorization requests that skipped PAR entirely, despite the Issuer advertising `require_pushed_authorization_requests: true`**: `AuthorizationServiceImpl.authorize` only used `request_uri` to decide *how* to process the request (via `pushAuthorizationRequestAuthorization` vs `processDirectAuthorization`) — it never checked whether PAR was actually required before falling back to the direct path, so a client could bypass the Pushed Authorization Request step by hitting `/oid4vci/v1/authorize` with plain query parameters, contradicting the Issuer's own metadata (RFC 9126 §5: an AS that requires PAR MUST reject a non-PAR authorization request). Caught by the OIDF conformance suite's `fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails` test — a direct request without `request_uri` was accepted and redirected back with a valid code instead of being rejected. Now `authorize` rejects with `OAuthTokenException.invalidRequest("Pushed Authorization Request is required")` (`400 invalid_request`) before ever reaching `processDirectAuthorization`, whenever the profile's `authorizationCode().requirePar()` is `true`. **Copilot review finding:** the new check's `OAuthTokenException` shape clashed with `AuthorizationServiceImpl`'s pre-existing `response_type`/PKCE/invalid-`request_uri` checks, which still threw plain `IllegalArgumentException` — mapped by `Oidc4vciExceptionHandler` to a different body (`GlobalErrorMessage` instead of `OAuthErrorResponse`), so `/oid4vci/v1/authorize` returned an inconsistent error schema depending on which validation failed. Converted the remaining three throw sites to `OAuthTokenException.invalidRequest(...)` too, matching the same standardization `ParServiceImpl` already went through earlier in this Story (see the `redirect_uri` entry below).
- **EUD-215 — `/oid4vci/v1/par` accepted an authorization request missing `redirect_uri`, which then crashed `/oid4vci/v1/authorize` with a `500`**: `PushedAuthorizationRequest` has no bean-validation constraint on `redirect_uri` (it is legitimately absent from other grant shapes) and `ParServiceImpl.pushAuthorizationRequest` never checked for it explicitly, so a PAR request without one was accepted with `201`. The missing value only surfaced downstream, once `/oid4vci/v1/authorize` redeemed the PAR and `AuthorizationServiceImpl.buildRedirectUri` called `new StringBuilder(redirectUri)` with a `null` — an uncaught `NullPointerException` instead of a clean rejection. Caught by the OIDF conformance suite's `fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails` test, which requires the request to fail with `invalid_request` at the PAR endpoint (the only automatable one of the test's three accepted outcomes — the other two need a manually uploaded screenshot of an error page or a redirect to a pre-registered `redirect_uri`, neither of which this Issuer implements). Added an explicit `redirect_uri` check to `ParServiceImpl`, alongside the existing `response_type`/PKCE checks, rejecting with `OAuthTokenException.invalidRequest("redirect_uri is required")` (`400 invalid_request`) before the request is ever stored.
- **EUD-215 — `/token` crashed with a `500` on an `authorization_code` grant whose code has no `issuer_state`**: `issuer_state` is OPTIONAL at the PAR/authorize level (RFC 9126 / OID4VCI 1.0) — a wallet-initiated authorization request never sends one — but `TokenServiceImpl.validateAndBuildAuthCodeToken` unconditionally called `issuerStateCacheStore.get(codeData.issuerState())` to resolve the `issuanceId` an access token is bound to. Guava's `Cache.getIfPresent` throws `NullPointerException` on a `null` key, which the generic catch-all turned into an opaque `500 "An unexpected error occurred"` instead of a proper OAuth2 error. Caught by the OIDF conformance suite's `fapi2-security-profile-final-happy-flow` test. Now checked explicitly before the cache lookup and rejected with `OAuthTokenException.invalidGrant(...)` (`400 invalid_grant`) — this Issuer can only complete an `authorization_code` exchange for a code tied to an Issuer-initiated credential offer, so a missing `issuer_state` is unusable here even though the parameter itself is spec-optional. `TokenServiceImplAuthCodeTest` already covered the `authorization_code` grant's happy paths (PKCE, DPoP) and other failure modes (invalid code, redirect_uri mismatch, PKCE failure); none exercised a code with no `issuer_state`, so this adds that regression case to the same class.
- **EUD-215 — `/credential` failed to parse a request using the `credential_identifier` addressing mode, returning a generic body with no `error` field**: OID4VCI 1.0 §8.2 defines `credential_configuration_id` and `credential_identifier` as mutually exclusive ways to identify the requested Credential — `credential_identifier` is used only when the Token Response returned `authorization_details` with `credential_identifiers`, which this Issuer never does (only the scope-based flow is implemented). `CredentialRequest` had no `credential_identifier` field at all and marked `credential_configuration_id` as JSON `required = true` unconditionally, so a request using `credential_identifier` failed Jackson deserialization outright (`400 "Failed to read HTTP message"`, no `error` field) instead of being recognized and cleanly rejected. Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-fail-unknown-credential-identifier` test. `credential_identifier` is now a recognized (nullable) field; since this Issuer can never resolve one, its mere presence is rejected with a new `UnknownCredentialIdentifierException` → `error="unknown_credential_identifier"` (OID4VCI 1.0 §8.3.1.2), checked before and independently of the `credential_configuration_id` guards below.
- **EUD-215 — `/credential` issued a credential for an unknown or mismatched `credential_configuration_id`, ignoring the request entirely**: `Oid4VciCredentialWorkflowImpl` computed whether the requested `credential_configuration_id` was registered (`knownRequestedConfigurationId`) but only ever used the result to decide what to log — the actual issuance always proceeded using `Issuance.getCredentialType()`, never checking it against what the client asked for. A request with a completely made-up `credential_configuration_id` got `200 OK` with a real, validly-signed credential; a request naming a *different but valid* configuration than the one the Issuance/token was actually authorized for (e.g. asking for PID with a LEAR Employee token) fared no better. Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-fail-unknown-credential-configuration` test. Now rejects both cases with `UnknownCredentialConfigurationException`, mapped by a new `Oidc4vciExceptionHandler` entry (scoped override of the `SharedExceptionHandler` version used by the backoffice credential catalog) to `error="unknown_credential_configuration"` — the exact code OID4VCI 1.0 §8.3.1.2 defines for this case (an earlier version of this fix used `unsupported_credential_type`, not a recognized code at all, flagged by the conformance suite as non-standard). The unknown case is rejected before the Issuance is even loaded; the mismatch case only after, since it needs the Issuance's own type to compare against.
- **EUD-215 — `/credential` proof errors used our internal Problem-Details body instead of the OID4VCI 1.0 §8.3.2 `{error, error_description, c_nonce, c_nonce_expires_in}` shape**: `InvalidOrMissingProofException`/`ProofValidationException` were mapped to our internal `GlobalErrorMessage` (`type`/`title`/`detail`/`instance`, no `error` field at all); `ProofValidationException` didn't even issue a fresh `c_nonce`. Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-fail-missing-proof` test (`VCIValidateCredentialErrorResponse`: required field `error` missing). New `CredentialErrorResponse` record backs both handlers now, mapping to `error="invalid_proof"` per spec and always including a fresh nonce. `/credential`'s error shape was explicitly called out as untouched in the PAR error-shape fix below — this closes that gap.
- **EUD-215 — client attestation JWTs missing the `sub` claim were silently accepted**: `ClientAttestationValidationService` extracted `client_id` from the WIA's `sub` claim but never checked it was present — with `sub` absent, `clientId` ended up `null` and validation continued anyway, so `PAR` returned `201 CREATED` with a `request_uri` instead of rejecting the request. Per `draft-ietf-oauth-attestation-based-client-auth`, `sub` identifies the OAuth client and is required. Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-fail-client-attestation-no-sub` test. Now throws `IllegalArgumentException("Client Attestation JWT missing sub claim")` when `sub` is null/blank, which the existing PAR error mapping already turns into a proper `invalid_client` OAuth2 error.
- **EUD-215 — `/credential` accepted a DPoP-bound access token without checking the DPoP proof matches the key it was bound to**: `dpopValidationService.validate(...)` was only ever invoked from `/par` and `/token` — never from `/credential`, the endpoint that actually returns the credential. A stolen DPoP-typed access token could be replayed with any key (or none) to fetch a credential, defeating DPoP's sender-constraining purpose at the one endpoint where it matters most. Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-happy-flow-multiple-clients` test ("Try Client1's DPoP key with Client2's access token" expected 400-499, got 200 with a signed credential in the body). `AccessTokenContext` now carries the token's `cnf.jkt` (extracted in `AccessTokenServiceImpl`); `CredentialController` reads the `DPoP` header and, when the resolved token is DPoP-bound, validates the proof and rejects (401, reusing `InvalidTokenException`) if it's missing or its key thumbprint doesn't match `cnf.jkt`. Tokens without `cnf.jkt` (DPoP not required for the tenant profile) are unaffected.
- **EUD-215 — PAR error responses used our internal Problem-Details-style body instead of the RFC 6749 §5.2 `{error, error_description}` shape RFC 9126 §2.3 requires**: the `IllegalArgumentException` → 400 mapping added for PAR (see below) fixed the status code but not the body shape — `/token` already had a proper `OAuthTokenException` → `OAuthErrorResponse` path for this, but `ParServiceImpl` still threw raw `IllegalArgumentException`, which the generic handler serializes as our own `GlobalErrorMessage` (no `error` field at all). Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-fail-invalid-client-attestation-signature` test (`CheckErrorFromParEndpointResponseErrorInvalidClientOrInvalidRequestOrInvalidClientAttestation`: 400 status was correct, but the required `error` field was absent). `ParServiceImpl` now throws `OAuthTokenException` (reusing the existing `/token` infrastructure) instead of `IllegalArgumentException`: `invalid_request` for response_type/PKCE/DPoP-proof failures, `invalid_client` for client attestation failures. `/credential`'s own error shape is untouched — this is scoped to the two OAuth2 endpoints (PAR, token) that RFC 6749 §5.2 governs.
- **EUD-215 — authorization codes did not meet the minimum entropy required by RFC 6749 §10.10 / RFC 6819 §5.1.4.2-2**: `AuthorizationServiceImpl` generated the `code` via `Utils.generateCustomNonce()`, which derives from `UUID.randomUUID()` — a version-4 UUID has 6 fixed version/variant bits out of its 128, so only 122 bits are actually random, and the OIDF conformance suite's Shannon-entropy check measured this short of its threshold (94.1 vs 96.0 required) on a live sample. Added a dedicated `Utils.generateSecureAuthorizationCode()` (32 bytes straight from `SecureRandom`, base64url-encoded) used only for the authorization code; `generateCustomNonce()` is untouched and still backs the credential offer id and pre-authorized code, which weren't flagged and didn't need the change.
- **EUD-215 — `/credential` rejected OID4VCI 1.0 Final requests with `400 Failed to read HTTP message`**: `CredentialRequest` required a top-level `format` field and only recognized the singular `proof`, both from an earlier draft of the spec. Per §8.2, `format` is no longer required once `credential_configuration_id` is present (the format is resolved from the referenced metadata entry), and the Final request shape uses `proofs` (plural, an object mapping proof type to a non-empty array — batch-issuance capable) instead of a single `proof` object. Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-happy-flow` test, which sends exactly this Final-shaped request. Made `format` optional and added a new `proofs` field (`Proofs.java`); `Oid4VciCredentialWorkflowImpl.extractFirstJwtProof(...)` now prefers `proofs[0]` when present, falling back to the legacy singular `proof`. The singular form is kept deliberately, not as a stopgap: `eudistack-core-wallet-pwa`'s `CredentialRequest.ts` still sends the older `format` + singular `proof` shape on its pre-authorized-code + PIN flow, and that path is explicitly called out as a critical path not to break — this is additive support for both client generations, not a temporary hack.
- **EUD-215 — PAR endpoint required a `DPoP` header, rejecting spec-compliant requests that defer proof-of-possession to `/token`**: per RFC 9449 §10.1, DPoP binding at the Pushed Authorization Request endpoint is optional — a client may send neither `dpop_jkt` nor a `DPoP` header there and instead bind the key on the token request only. `ParServiceImpl` unconditionally required `DPoP` whenever the tenant profile had `requireDpop` enabled, rejecting the OIDF conformance suite's (spec-compliant) request that omitted it. Now `DpopValidationService.validate(...)` is only invoked when a `DPoP` header is actually present; `requireDpop` still governs enforcement at the token endpoint.
- **EUD-215 — PAR/token/credential endpoints returned `500 Internal Server Error` instead of a `400` OAuth error on invalid client input**: `ParServiceImpl`, `DpopValidationService`, `ClientAttestationValidationService` and `PkceVerifier` raise plain `IllegalArgumentException` for malformed requests (missing DPoP proof, invalid client attestation, PKCE mismatch...), but neither `@RestControllerAdvice` mapped that type — it fell through to the generic catch-all 500 handler. Caught by the OIDF conformance suite's `oid4vci-1_0-issuer-happy-flow` test, which expects a `400` response per RFC 9126 §2.2–2.4 for a bad Pushed Authorization Request. Added an `IllegalArgumentException` handler to `Oidc4vciExceptionHandler`, scoped via `@RestControllerAdvice(basePackages = "...oidc4vci.infrastructure.controller")` so it only reclassifies this exception for the OID4VCI protocol endpoints — `IllegalArgumentException` thrown elsewhere in the app (signing, status list, tenant config...) is unaffected and still surfaces as a 500.
- **EUD-215 — Authorization Server metadata missing required client attestation signing algorithm fields (OAuth 2.0 Attestation-Based Client Authentication §10.1)**: `token_endpoint_auth_methods_supported` advertises `attest_jwt_client_auth` by default, which requires also declaring `client_attestation_signing_alg_values_supported` and `client_attestation_pop_signing_alg_values_supported` — neither existed on `AuthorizationServerMetadata`. Caught by the OIDF conformance suite's issuer metadata test for EUD-215, right after the matching well-known routing/security fix landed. Both new fields added to the record and populated with `["ES256"]` in `AuthorizationServerMetadataServiceImpl`, only when `clientAuthMethod` is `attest_jwt_client_auth` (stay `null`/omitted otherwise, e.g. for `"none"`).
- **EUD-215 — well-known metadata endpoints rejected `Accept: application/jwt` with 406, then 500, instead of degrading to plain JSON**: signed metadata (OID4VCI 1.0 §12.2.3) is optional and not implemented; the conformance suite's `-signed` test module expects a normal response it can inspect (and then skip its signed-only assertions on), not a hard rejection. Adding `MediaType.ALL_VALUE` alongside `APPLICATION_JSON_VALUE` to `produces` fixed route matching (no more 406) but Spring still tried to negotiate the response's `Content-Type` against the requested `Accept` during the write phase, and since no converter can serialize a Java record as `application/jwt`, that failed with `HttpMessageNotWritableException` → 500. `CredentialIssuerMetadataController` and `AuthorizationServerMetadataController` now return `Mono<ResponseEntity<T>>` with an explicit `.contentType(MediaType.APPLICATION_JSON)`, which Spring treats as authoritative and writes unconditionally — the plain JSON body is now actually served regardless of the requested `Accept`. Implementing real signed metadata (own local signing key + JWKS exposure, separate from the remote QTSP/CSC pipeline used for credentials) is deliberately deferred as its own future scope, not part of this Story.

- **EUD-215 — well-known metadata endpoints now accept the issuer's own path as a suffix (OID4VCI 1.0 §12.2.2)**: a compliant client derives the metadata URL by inserting the well-known path *before* the issuer's own path when the `credential_issuer` identifier has one (e.g. `/.well-known/openid-credential-issuer/issuer` for an issuer at `https://host/issuer`), not by appending it after. `SecurityConfig`'s `permitAll()` list and both metadata controllers (`CredentialIssuerMetadataController`, `AuthorizationServerMetadataController`) only ever matched the bare `/.well-known/openid-credential-issuer` form, so a spec-compliant request landed on a `401 Not Authenticated` — the broader `/.well-known/**` `securityMatcher` still claimed it before `authorizeExchange` rejected it for lacking an exact-path match. Confirmed against the real OIDF conformance suite run for EUD-215, right after the matching CloudFront/ALB routing fix landed in `eudistack-platform-iac` (the suite got past the routing 403 only to hit this 401 next). New `*_WELL_KNOWN_WILDCARD_PATH` constants (`EndpointsConstants`, same naming pattern as `ISSUANCES_PATH`/`ISSUANCES_WILDCARD_PATH`) added alongside the existing bare-path ones rather than editing them in place — those are also used to build literal request URLs in `SecurityConfigTest`, where appending `/**` would have produced a broken literal path instead of a pattern. Covers both well-known endpoints (credential issuer metadata, and authorization server metadata under both its RFC 8414 and legacy OID4VCI paths).

- **Legacy credential type names no longer break id_token validation on the certification policy**: issuing `gx.labelcredential.w3c.2` failed with `400 invalid_credential_format` — `No profile found for credential type: LEARCredentialEmployee` — whenever the `X-ID-Token` carried a legacy DOME LEAR Credential Employee. `RequireCertificationIssuanceRule` re-derives the credential type from the `type` array of the VC embedded in the id_token's `vc_json` claim, and `DynamicCredentialParser` looked that value up **only** through `CredentialProfileRegistry.getByConfigurationId`. Modern profiles encode the configuration id inside `credential_definition.type`, so that lookup coincided by construction; legacy credentials carry a human-readable type (`LEARCredentialEmployee`) that exists only in the credential-type index.
  - `CredentialProfileRegistry.resolveProfile(String)`: single resolution entry point that tries the configuration-id index and falls back to the credential-type index. `DynamicCredentialParser.parse` and `PolicyContextFactory.resolveProfile` now both go through it, removing the asymmetry that left the access-token path tolerant (it already had the fallback) and the id_token path brittle (it did not).
  - No behavioural change on the access-token path: `PolicyContextFactory` keeps the same two-step lookup it already performed, delegated instead of duplicated.
  - Ambiguity left as-is deliberately: `learcredential.employee.w3c.2` and `w3c.3` share the `LEARCredentialEmployee` type, so the credential-type index keeps whichever profile loads first and logs `Multiple profiles share credential type`. Harmless today — both declare an identical `policy_extraction` — and only worth revisiting if two profiles sharing a type ever diverge in `policy_extraction`, `validation` or `issuance_policy`.
  - Known remaining gap (not addressed here): the certification rule still needs to resolve a profile just to learn the `policy_extraction.powers_path`, so any credential whose `type` is absent from the registry keeps failing the same way, even though the verifier already publishes the powers as a top-level `power` claim in the same signed id_token.
  - Tests: `CredentialProfileRegistryTest` (resolution by configuration id, by legacy type name, `null` for unknown identifiers), `DynamicCredentialParserTest` (new — legacy and modern `type` arrays, missing and empty `type`, power extraction through `policy_extraction`).


### Added - 05-08-2026

- **OTLP log export to OpenObserve**: logs now flow through the same OTel Collector pipeline already used for traces/metrics, so `business.issuance.credential` and every other INFO+ log line become queryable by SQL in OpenObserve instead of living only as plain text in CloudWatch. New `MaskingOpenTelemetryAppender` (`shared/infrastructure/config/logging`, extends `io.opentelemetry.instrumentation.logback.appender.v1_0.OpenTelemetryAppender`) wraps every `ILoggingEvent` (`DelegatingLoggingEvent`, new) to mask the rendered message and every MDC value through `MaskingPatternLayout.mask` before export — the OTel appender reads the raw event, bypassing the `MaskingPatternLayout`/`MaskingJsonGeneratorDecorator` the console appenders use, so redaction has to happen here or JWTs/emails/tokens would reach OpenObserve unmasked. MDC values are re-assembled as `"key=value"` before masking, because `MaskingPatternLayout`'s sensitive-key patterns (`tx_code`, `access_token`, `password`, `client_secret`, `secret`, …) only fire when key and value appear together in one string — an MDC map hands them over as separate entries. New `OpenTelemetryAppenderInitializer` (`@Component implements InitializingBean`) calls `OpenTelemetryAppender.install(openTelemetry)` on startup — Logback initializes before the Spring context, so the appender has no SDK to export to until this runs. Wired via `management.otlp.logging.{endpoint,transport,export.enabled}` (new `MANAGEMENT_OTLP_LOGGING_EXPORT_ENABLED`/`MANAGEMENT_OTLP_LOGGING_TRANSPORT` env vars, defaulting to off so local runs/tests never attempt export), reusing the existing `OTEL_COLLECTOR_GRPC_URL` — no new SSM parameter, IAM change, or security group rule needed. New `OTLP` appender in `logback-spring.xml`, referenced from `<root>` in both `springProfile` branches, gated at INFO via a `ThresholdFilter` — STG runs `es.in2.issuer` at DEBUG and shipping that volume to OpenObserve is pure S3 cost with no signal. Both new classes added to `ArchUnitTest`'s unreferenced-class whitelist (`MaskingOpenTelemetryAppender` is referenced only by class name from `logback-spring.xml`; `OpenTelemetryAppenderInitializer` is a Spring-managed bean discovered via component scanning). Tests: `MaskingOpenTelemetryAppenderTest` (new), covering JWT/email masking in the message, key-name-only secrets in MDC (validates the key=value re-assembly), non-sensitive MDC passthrough, and `getArgumentArray()` nulled out so no downstream consumer re-renders the unmasked original.

## [3.6.27] - 2026-08-04

### Added

- **EUD-170 — Trace the delivery mode applied per issuance (FR-10, NFR-O-01, NFR-S-02)**: hardens the delivery audit trail that EUD-167/168/169 already partially emitted, so every issuance leaves a complete, consistent, PII-safe trace of *how* it was delivered.
  - `DeliveryTrace` (new, `issuance/domain/model`): immutable, PII-safe-by-construction aggregate of `Set<DeliveryResult>` + `tenantId` + `processId`; stable event name `credential.delivered`; rejects a blank tenant/processId or empty results at construction time; `hasFailure()` decides audit severity.
  - `RecipientPseudonymizer` (new, `shared/domain/util`): HMAC-SHA256 hash of a recipient identifier salted with the tenant id, per AD-2 (data minimization by default — omit the recipient; pseudonymize only if correlation is ever required). Not wired to any caller yet — nothing currently needs recipient correlation.
  - `AuditService.auditDelivery(DeliveryTrace)` (new port method) / `AuditServiceImpl.auditDelivery` (adapter): emits a structured `AUDIT` log line (`event=credential.delivered tenant.id=... processId=... results=...`) at `INFO` when every mode delivered, `WARN` when any mode failed; wrapped in try/catch so a broken audit channel is logged locally and never propagates (ES-03/ES-04).
  - `IssuanceWorkflowImpl#issueCredential`: now fails closed with a new `TenantNotResolvedException` (403) *before* validating, building or delivering anything when the Reactor context carries no tenant — previously the operation completed anyway and just omitted the tenant field (AC-05/ES-02). Replaces the previous `auditSuccess("credential.issued", ...)`/`auditFailure("credential.issue.failed", ...)` calls with `auditDelivery(DeliveryTrace)` in both the success and error paths; a partial hybrid failure (e.g. wallet leg fails, direct leg delivers) still completes the `Mono` successfully but is now correctly traced as a failure (`WARN`) via `DeliveryTrace.hasFailure()`, since `performOid4VciIssuanceResilient` already absorbs the wallet error into a `FAILED` `DeliveryResult` rather than erroring the chain.
  - `IssuanceMetrics#recordSuccess`/`recordError`: added the canonical `tenant.id` tag (`conv-observability.md` §3) alongside the pre-existing `tenant` tag on `issuance.duration`/`issuance.requests` — additive, scoped to these two methods only.
  - **Out of scope (see `spec-deltas.md` D-6)**: `issueCredentialWithoutAuthorization` (bootstrap/LEAR pre-registration path) is not touched — it still emits no delivery trace at all. Left as an open, explicit gap pending a PM/Architect decision, not silently forgotten.
  - **EC-04 (idempotency)** required no new production code or test: `IdempotencyFilter` short-circuits a cache-hit entirely above the controller/workflow, so `auditDelivery` structurally cannot be invoked twice for the same idempotency key — already demonstrated by the pre-existing `IdempotencyFilterTest.replayWithSameKey_returnsCachedBody_andInvokesChainOnce`.
  
 - Tests: `DeliveryTraceTest`, `RecipientPseudonymizerTest`, `AuditServiceImplTest` (new files), plus `IssuanceWorkflowImplTest` (tenant fail-closed, hybrid partial-failure severity, wallet-only trace, audit-channel-failure resilience) and `IssuanceMetricsTest` (`tenant.id` tag) extended.

### Added - 2026-08-03
- Chance issuance metrics by logs

### Fixed - 2026-07-30

- **EUD-71 — Select form and issue credential (conformance reinforcement)**: the issuance flow (`IssuanceWorkflowImpl`) already satisfied AC-03/AC-04 on the backend side; this Story adds 2 conformance tests to `IssuanceWorkflowImplTest` (persistence of `credential_format` on direct `dc+sd-jwt` issuance, persistence of the catalog's `credential_configuration_id` as `credentialType` on OID4VCI issuance) to close the documented coverage gap. No production code change — this Story consumes EUD-72's catalog and requires no new endpoints.
- **Documented tech debt (non-blocking)**: the `IssuanceController_IT` integration test (`WebTestClient` + Testcontainers) planned in `tasks.md` is postponed. Investigation found no Testcontainers integration test anywhere in the repository, nor the base package/class the enriched documentation assumed as a starting point; building it is a new infrastructure effort, not an L-sized task. The HTTP contract (incl. 400/401) is already covered by `IssuanceControllerTest` (mocks); ES-02 (403 via real PDP) remains a known integration-coverage gap, with no automated test yet.

### Added

- **Business event log for issued credentials**: new `CredentialIssuedLogger` (domain port `shared/domain/service` + `CredentialIssuedLoggerImpl` in `shared/infrastructure/service`, following the same interface/impl split as `AuditService`) logs one line per credential issuance outcome — `event=business.credential.issued tenant=<tenant> configurationId=<id> outcome=ok|error` (`errorType=<SimpleName>` added on failure). Tenant is resolved from MDC (`tenantDomain`, bridged from the Reactor context by `MdcContextConfig`), with `unknown` as fallback for tenant/configurationId, matching the previous counter's semantics.
  - Logged at the two places a credential is actually signed and handed to the holder: `Oid4VciCredentialWorkflowImpl.createCredentialResponse` (OID4VCI `/credential`, where the wallet collects the credential) and the direct-delivery leg of `IssuanceWorkflowImpl.executeIssuanceForModes` (the signed credential returned synchronously in the API response). A credential offer dispatched by email/UI does **not** log — no credential exists yet at that point.
  - **Replaces** the previous Micrometer counter `business.credential.issued` in `IssuanceMetrics` (tags `tenant`/`configuration_id`/`outcome`), removed along with its defensive `try/catch` + one-shot failure-log guard — a plain `log.info`/`log.warn` call cannot throw the way `MeterRegistry.register` could on a meter-type collision. `issuance.requests`, `issuance.duration`, `oid4vci.token.requests` and `idempotency.cache.hits` are unaffected.
  - Tests: `CredentialIssuedLoggerImplTest` (new, Logback `ListAppender`: event/tenant/outcome/errorType content, `unknown` fallbacks), `Oid4VciCredentialWorkflowImplTest` and `IssuanceWorkflowImplTest` (`verify()` on the mocked `CredentialIssuedLogger` instead of counter assertions).

- **EUD-72 (US-02) — Tenant credential catalog admin API**: a tenant administrator can now read and replace the set of credential types enabled for their own tenant, without a redeploy or a manual DB change.
  - `CredentialCatalogController`: new `GET`/`PUT /admin/v1/credential-catalog`. The tenant is always taken from the reactive context (`TenantDomainWebFilter`), never from the request body. `GET` requires `isTenantAdmin()` only — a SysAdmin operating from the platform tenant keeps its cross-tenant read-only view; `PUT` additionally requires `canWrite()`, so that same read-only SysAdmin gets `403`.
  - `TenantCredentialProfileService.getCatalog()`: returns the **full global registry**, each entry flagged `enabled` for the current tenant (`CredentialCatalogEntryDto`: `credentialConfigurationId`, `displayName`, `enabled`), sorted by display name. `displayName` falls back to the configuration id when the profile has no `credentialMetadata.display[0].name` (no i18n yet).
  - `TenantCredentialProfileService.updateCatalog(Set<String>)`: full replace of the tenant's enabled ids. Validates `enabledConfigurationIds ⊆ CredentialProfileRegistry` **before** touching the DB (unknown id ⇒ error, zero writes), then performs an atomic `deleteAll + insert`, and invalidates the tenant's Caffeine entry only after a successful commit. `PUT` with an empty set is rejected upfront by bean validation (`@NotEmpty` on `UpdateCredentialCatalogRequest`); the empty set stays reachable on the service as the reset primitive.
  - `R2dbcTransactionConfiguration`: first reactive transaction wiring in the Issuer (`R2dbcTransactionManager` + programmatic `TransactionalOperator`; `@EnableTransactionManagement` intentionally omitted since no declarative `@Transactional` is used). Needed so a failure mid-replace rolls back instead of leaving the tenant with zero rows. The transactional connection is borrowed once via `ConnectionFactory.create()`, which is where `TenantAwareConnectionFactoryDecorator` sets the per-tenant `search_path`, so every statement of the transaction runs against the right schema.
  - `SharedExceptionHandler` / `GlobalErrorTypes`: new RFC-7807 mappings — `UnknownCredentialConfigurationException` → 400 `unknown_credential_configuration`, `CredentialCatalogNotConfiguredException` → 404 `credential_catalog_not_configured`.
  - `SecurityConfig`: `CREDENTIAL_CATALOG_PATH` registered in both `customAuthenticationWebFilter`'s matcher and `unifiedFilterChain`'s security matcher (authenticated, not public), same as EUD-169's delivery-config path.
  - Migration `V9__Add_updated_at_to_tenant_credential_profile.sql`: adds `updated_at TIMESTAMPTZ`, backfills existing rows from `created_at`, then sets `DEFAULT now()` + `NOT NULL`. `TenantCredentialProfile` gained the matching `updatedAt` component; the application stamps both timestamps on each `updateCatalog` write.
  - Tests: `TenantCredentialProfileServiceImplTest` (catalog projection, display-name fallback, unknown-id rejection with no write, cache invalidation only after commit, missing-tenant rejection), `CredentialCatalogControllerTest` (authz matrix for GET/PUT, `@NotEmpty` rejection, error mappings), `CredentialCatalogTransactionalIT` (Testcontainers: committed write readable back from the tenant schema, isolation between tenants, idempotent re-apply of the same set, rollback to the previous state on a mid-replace failure), `CredentialIssuerMetadataServiceImplTest` (updated for the new empty-catalog semantics), `ArchUnitTest` (allow-listed `R2dbcTransactionConfiguration`, whose beans are consumed by injection only).

### Changed

- **BREAKING (operational) — an unconfigured tenant catalog now means "nothing enabled", not "everything enabled"**: the `tenant_credential_profile` table used to be interpreted as an optional filter, so a tenant with zero rows was implicitly allowed to issue every credential type in the global registry. That backward-compatibility fallback is gone; the catalog must now be configured explicitly.
  - `TenantCredentialProfileServiceImpl`: `getAvailableProfiles()` returns an empty map and `isProfileAllowed(...)` returns `false` when the tenant has no enabled id (previously: all profiles / always `true`).
  - `RequireCredentialProfileAllowedForTenantRule` (PDP): an unconfigured tenant no longer passes the rule for any credential type — issuance is denied instead of silently allowed.
  - `CredentialIssuerMetadataServiceImpl`: `/.well-known/openid-credential-issuer` advertises an empty `credential_configurations_supported` for an unconfigured tenant instead of the full global set, so wallets no longer see types the tenant was never meant to issue.
  - `GET /admin/v1/credential-catalog` answers **404 `credential_catalog_not_configured`** when no entry is enabled — covering both a never-configured tenant and one whose stored ids are all unknown to the registry.
  - **Deployment note:** every existing tenant must have its rows seeded in `tenant_credential_profile` (done in `eudistack-platform-dev`, alongside the other tenant seeds) before this version is rolled out; otherwise that tenant stops issuing and advertises no credential configurations. The change is fail-closed by design — the previous behaviour let a misconfigured tenant issue the entire catalog.
  - Cache note: enabled ids are cached per JVM (Caffeine, 5 min TTL) and `updateCatalog` invalidates only the local entry, so on a multi-replica deployment other replicas converge within the TTL.

## [3.6.26] - 2026-07-29

### Added

- **EUD-168 — Direct delivery of holder-bound credentials (FR-06, FR-02, FR-08)**: credential types requiring cryptographic holder binding (`cnfRequired`) can now be delivered directly. The request carries the holder's public key in a new optional `holder_key` field, normalized by the `HolderKey` value object into the RFC 7800 `cnf` claim (exactly one of `jwk`/`kid`/`x5c`) and validated fail-fast before anything is built, signed or persisted. `IssuanceWorkflowImpl` threads that `cnf` into `signCredential(...)` where the direct path previously passed `null`; the issuer's signature is unchanged, so verifiability is preserved and identical to a wallet-delivered credential.
  - **Supersedes EUD-169's hard rule**: the `cnfRequired`-excludes-`direct` exclusion is now a *default*, not an absolute rule. Eligibility is governed by tenant config (`issuer.delivery.modes.<credential_configuration_id>`); a tenant admin may explicitly enable `direct` for a `cnfRequired` type. Behaviour: no config → `409 delivery_mode_not_eligible`; config enabling `direct` but missing/malformed key → `400 invalid_holder_key` (`InvalidHolderKeyException`); config + valid key → `200` signed with `cnf`. Non-binding, wallet-only and hybrid paths are unchanged; signer/persistence/config-read failures stay fail-closed.

## [3.6.25] - 2026-07-28

### Added

- **EUD-169 — Configure eligible delivery modes per tenant/credential type (FR-09, FR-02)**
  - `TenantDeliveryConfigService` / `TenantDeliveryConfigServiceImpl`: tenant admins can now persist which delivery modes (`direct`, `email`, `ui`) are eligible for a given `credential_configuration_id`, stored under the `tenant_config` key `issuer.delivery.modes.<credential_configuration_id>` — the same key EUD-167's issuance-time eligibility check reads, so admin changes take effect without a redeploy. No new DDL.
  - `DeliveryEligibilityResolver`: resolves the effective eligible set for the `GET` admin endpoint as the tenant's configured modes, or a `cnfRequired()`-aware default (`email,ui` vs `direct,email,ui`) when no explicit configuration exists — kept consistent with the default EUD-167 applies at issuance time.
  - `DeliveryMode.toCanonicalCsv(Set<DeliveryMode>)`: canonical, deduplicated, alphabetically-sorted CSV serialization; round-trips with the existing `DeliveryMode.parse(String)`.
  - `DeliveryConfigController`: new `GET`/`PUT /api/v1/backoffice/delivery-config/{credentialConfigurationId}` endpoints for a TenantAdmin to view and set the eligible modes for a credential type in their own tenant — `403` for non-admin callers, `404` for an unknown or tenant-disabled `credential_configuration_id`, `400` for an empty or unrecognized mode set.
  - `SharedExceptionHandler` / `GlobalErrorTypes`: new RFC-7807 mappings — `InvalidDeliveryConfigException` → 400 `invalid_delivery_config`, `DeliveryConfigProfileNotFoundException` → 404 `delivery_config_profile_not_found`.
  - `SecurityConfig`: registered the new backoffice path in both `customAuthenticationWebFilter`'s matcher and `unifiedFilterChain`'s security matcher (authenticated, not public) — required for the endpoint to receive CORS/security headers and go through the standard auth filter.
  - Integration with EUD-167's `IssuanceWorkflowImpl#resolveAndValidateDeliveryModes`: the `cnfRequired` exclusion of `direct` is now a hard rule enforced even when a tenant admin has explicitly configured `direct` for such a credential type — an explicit override cannot bypass the cryptographic-binding requirement.
  - Tests: `DeliveryModeTest` (canonical CSV, `isDirect`, parse edge cases — merged with EUD-167's coverage), `TenantDeliveryConfigServiceImplTest` (upsert, replace-not-merge, tenant key isolation, ES-01/ES-06), `DeliveryEligibilityResolverTest` (AC-02/03/05, EC-04, fail-closed), `DeliveryConfigControllerTest` (authz guards, ES-01..04), `IssuanceWorkflowImplTest` (regression test for the explicit-override hard rule), `SharedExceptionHandlerTest` (new error mappings).
  - Token tag in metrics.

## [3.6.24] - 2026-07-23

### Added (23-07-2026)

- **Direct & hybrid credential delivery (EUD-167)**: form-based issuance can now return the signed credential synchronously in the `POST /api/v1/issuances` response, with no wallet involved. The request declares one or more `delivery` modes (`direct`, `email`, `ui`); **hybrid** is the presence of ≥2 modes (e.g. `direct,email`), delivering the credential directly **and** dispatching the wallet offer in a single operation. The response carries an explicit per-mode `delivery_results` array (`{mode, status, error?}` with `delivered`/`dispatched`/`failed`), added additively to `IssuanceResponse` so existing clients are unaffected. The hybrid wallet path is isolated with `.timeout(issuance.hybrid-wallet-timeout-seconds, default 30s).onErrorResume(...)`, so a wallet failure or timeout reports `wallet=failed` without invalidating the already-delivered direct credential (0 inconsistent issuances); the direct path stays fail-closed on signing/persistence errors. Delivery-mode eligibility is validated **before** signing/dispatching/persisting via a per-tenant key `issuer.delivery.modes.{credentialConfigurationId}` (read from `TenantConfigService`, safe default derived from `cnfRequired()`): an unknown/blank mode returns `400 invalid_request` (`InvalidDeliveryModeException`) and a non-eligible mode returns `409 delivery_mode_not_eligible` (`DeliveryModeNotEligibleException`). Directly delivered credentials are persisted with their revocation status pointer (revocable without re-issuance). `IdempotencyFilter` now caches and replays the full response body (not just status + `Location`), so a retry with the same `X-Idempotency-Key` returns the identical result without a duplicate issuance. Issuance audit events (`credential.issued` / `credential.issue.failed`) now record delivery mode, per-mode outcome and tenant, without the recipient's e-mail. Wallet-only issuance returns `202` with the `delivery_results` body instead of an empty response.

## [3.6.23] - 2026-07-22

### Added

- **API Client — M2M authentication gate for unattended issuance intake (EUD-75 / US-02)**:
  - External systems can now authenticate as a registered API client via `POST /oauth/token` with `grant_type=client_credentials`, receiving a short-lived (≤ 5 min) JWT with `caller_type=M2M` and `can_trigger_issuance` claims.
  - New `api_client` table (schema-per-tenant, `V8__Add_api_client_table.sql`) with `authorization_status` (`ACTIVE`/`REVOKED`/`SUSPENDED`) and BCrypt-hashed secrets.
  - `IntakeCallerAuthorizationFilter` gates `/api/v1/intake` (endpoint itself lands with EUD-74): `403` if the token isn't `M2M` or lacks `can_trigger_issuance`, `401` if unauthenticated/expired/unknown-issuer — fail-closed on repository failure.
  - Uniform `invalid_client` response for a non-existent `client_id` vs. an incorrect secret, to prevent client enumeration.
  - Every gate decision (admitted or rejected) is audited with tenant, caller identity, result and cause — never the secret or full token.

## [3.6.22] - 2026-07-22

### Added

- **EUD-98 — Know the result of the revocation and leave a trace of the reason**
  - `RevokeCredentialRequest`: added optional/nullable `reason` field (backward-compatible) so the operator's revocation reason can be traced (AC-07, EC-01).
  - `RevocationAuditDetails`: new value object building the audit details map per conv-quality-security-gates §10.2, with PII redaction by design (never accepts `Issuance`, only primitives) and reason sanitization (truncated to 280 chars, `"not-provided"` marker when absent/blank) (AC-04, AC-07, EC-01, ES-01).
  - `AuditService` / `AuditServiceImpl`: new `auditAttempted` method, reusing the existing `AUDIT` logger + MDC pattern — no new event bus (AC-03).
  - `RevocationWorkflow`: resolves the operator identity via `ReactiveSecurityContextHolder` (fallback `"unknown"` + `WARN` log when not resolvable, EC-02); emits `credential.revoke.attempted` right after loading the issuance (or before the 404 on a missing one); enriches `credential.revoked` (success) with the resolved operator, the credential's organization/tenant and the sanitized reason, replacing the previous `userId=null` minimal audit; emits `credential.revoke.failed` on any denial or execution error, with a categorized `error.type` (`invalid_status`, `unauthorized_role`, `tenant_mismatch`, `issuance_not_found`) and no stacktrace/PII, without altering the HTTP error mapping owned by EUD-97 (R-2); both audit emissions are wrapped in try/catch so a logging failure never reverts or fails an already-consumed revocation (ES-04).
  
 - Tests: new `RevocationAuditDetailsTest`; extended `RevocationWorkflowTest` with audit content, attempted→success/failed ordering, unknown-actor fallback, categorized failure and ES-04 assertions (AC-01, AC-02, AC-03, AC-07, EC-02, ES-04).

### Added

- **Per-tenant email language**: transactional emails are now localized per tenant instead of using a single global value. A new `issuer.default_lang` key in `tenant_config` (supported: `en`, `es`) drives the locale for every email — subject and template rendering. When the key is absent, blank, or unsupported for a tenant, it falls back to the global `APP_DEFAULT_LANG` (default `en`), so existing tenants are unaffected. `EmailServiceImpl` resolves the language reactively (alongside `issuer.mail_from`) while inside the tenant-scoped Reactor context, and threads the resolved locale into the Thymeleaf `Context` and into the new `TranslationService.translateWithLocale(...)` / `getLocaleOrDefault(...)` methods. Flyway migration `V7__Seed_default_lang.sql` seeds a placeholder `issuer.default_lang = 'en'` per tenant; real per-tenant values are set in the sibling `eudistack-platform-dev` repo (`postgres/seed-tenants[.stg].sql`).
  - Note: the locale-aware API is named `translateWithLocale(code, locale, args)` (not a `translate` overload) on purpose — an overload with a `String locale` before `Object... args` is ambiguous with `translate(code, args)` under Java varargs resolution and would silently capture a string message argument as the locale.

## [3.6.21] - 2026-07-16

### Added

- **EUD-97 — Protect revocation against non-revocable states and out-of-scope credentials**
  - `SharedExceptionHandler`: `UnauthorizedRoleException` now maps to **403 Forbidden** (was 401) — an authenticated operator denied by scope/capability is a permissions issue, not an authentication failure (AC-03, AC-05).
  - `SharedExceptionHandler`: new handler for `InvalidCredentialStatusTransitionException` → **409 Conflict** with a readable detail, instead of falling through to the catch-all 500 (AC-06, ES-03).
  - `GlobalErrorTypes`: added `INVALID_CREDENTIAL_STATUS_TRANSITION` error code.
  - `RevocationWorkflow`: revoking a non-existent `issuanceId` now returns **404 Not Found** (`IssuanceNotFoundException`) instead of silently completing (ES-02).
  - `RevokeCredentialRequest` / `BitstringStatusListController`: `issuanceId` is now validated as non-blank (`@NotBlank` + `@Valid`), returning **400 Bad Request** for empty/missing values (ES-01).
  - Tests: `RequireValidStatusRuleTest` (parametrized over all non-VALID statuses), `BitstringStatusListControllerRevokeIT` (first Testcontainers-based integration test in this repo — covers AC-01..AC-06, EC-01, EC-03, ES-01, ES-02 end-to-end against a real Postgres and the real security filter chain).

### Tests (25-06-2026)

- **Archive terminated procedures**: Added unit tests for `CredentialStatusEnum` covering ARCHIVED→ARCHIVED rejection, WITHDRAWN/REVOKED/EXPIRED→ARCHIVED allowed transitions, and ARCHIVED having no outgoing transitions (EC-02, ES-01).

## [3.6.20] - 2026-06-19

### Changed

- **OID4VCI — Credential Issuer Metadata**: Added `deferred_credential_endpoint` field to the `/.well-known/openid-credential-issuer` response. The endpoint URL is derived from the public issuer base URL at runtime, consistent with the other OID4VCI endpoint fields.
- **CredentialOfferWorkflow**: Added structured log lines in `CredentialOfferWorkflowImpl.findCredentialOfferById` to trace TX code notification dispatch — `INFO` when a TX code is present and the notification email is sent, `DEBUG` when no TX code is found and the email step is skipped.

### Added

- Observability configuration

### Fixed

- **OID4VCI — nonce consumed before signature validation**: `ProofValidationServiceImpl.verifyProof()` deleted the nonce from the cache before verifying the JWT signature. A 502 mid-flight caused the nonce to be lost; any subsequent retry propagated as `ProofValidationException("Error during JWT validation")` (generic catch) instead of surfacing the root cause. Refactored into a two-step flow: `checkNonce()` verifies the nonce exists but does NOT delete it; deletion only happens after `validateSignatureAccordingToHeader()` succeeds. Tests updated to assert the nonce is not consumed on signature failure.
- **OID4VCI — `CacheStore.get()` emits error on cache miss**: `CacheStore.get()` returned `Mono.error(NoSuchElementException)` when the key was absent. Callers using `.switchIfEmpty()` never saw the empty signal — `switchIfEmpty` only fires on `Mono.empty()`, not on `Mono.error()` — so a cache miss bypassed the intended error mapping and propagated as an uncaught exception. Fixed to return `Mono.empty()` on miss. All callers that previously relied on `onErrorMap(NoSuchElementException.class, ...)` migrated to `switchIfEmpty(Mono.error(...))` (`AuthorizationServiceImpl`, `TokenServiceImpl` — 5 sites).

### Fixed (23-06-2026)

- **OID4VCI — Wallet deep-link in activation email**: the wallet base URL embedded in the credential-offer email (`{wallet}/protocol/callback?credential_offer_uri=...`) is now resolved per the topology the request arrived through, via the new `UrlResolver.publicWalletBaseUrl()`, instead of the static `issuer.wallet_url` tenant-config value. Previously a tenant accessed through a non-canonical custom domain received an email pointing at whatever single URL was stored in `tenant_config`, mismatching the domain the user actually used. Resolution is keyed on the **request host** (not the `X-Tenant` header, which carries the same tenant id for every domain a tenant is reached through and therefore cannot tell canonical from custom): if the host matches a custom-domains registry entry's `issuer` host, the entry's `wallet` URL is returned (non-canonical, separate wallet host); otherwise it falls back to `requestOrigin + /wallet` (canonical, path-based — issuer and wallet share the origin). Same registry-backed mechanism as `expectedVerifierBaseUrls`. `TenantCustomDomainsLoader` exposes a new host→wallet index (`findWalletUrlByIssuerHost`). `publicWalletBaseUrl` is threaded through `IssuanceController` / `BootstrapController` / `CredentialOfferRefreshController` → `IssuanceWorkflow` / `CredentialOfferRefreshWorkflow` → `CredentialOfferService.createAndDeliverCredentialOffer`. The `issuer.wallet_url` tenant-config lookup is no longer used for the deep link.

### Fixed (19-06-2026)

- **PBAC — Legacy credential resolution**: `PolicyContextFactory.resolveProfile` now falls back to `CredentialProfileRegistry.getByCredentialType(...)` when no profile matches by `credential_configuration_id`. Real DOME legacy credentials carry the bare semantic type in `type[]` (e.g. `LEARCredentialEmployee`) instead of the versioned config-id, so policy evaluation previously rejected them with `InvalidCredentialFormatException: No profile found for credential type`. Required for the dual-format read flow during the DOME sunset window.
- **Tenant search path**: `TenantAwareConnectionFactoryDecorator` now wraps the resolved schema name in double quotes when issuing `SET search_path`, preventing case-sensitivity mismatches and identifier-syntax failures for tenants whose schema requires explicit quoting.

### Changed (19-06-2026)

- **Credential profile loading**: `CredentialProfileRegistry` now recursively scans `${credential.profiles.path}/**/*.json` (previously only the top-level directory) so DOME legacy profiles dropped under `legacy/` subfolders are picked up automatically. Sample profiles matching `*.sample*.json` are skipped to avoid polluting the registry with fixture data.
- Accept multiple verifier URLs to validate `iss` in the access token.

### Fixed (18-06-2026)
- **OID4VCI — Credential Offer URL**: `UrlResolverImpl.publicIssuerBaseUrl()` now derives the public URL from `issuerContextPath` (`spring.webflux.base-path`) instead of the `X-Tenant` header. CloudFront injects `X-Tenant` on all ALB-bound requests, including canonical deployments (e.g. `sandbox.stg.eudistack.net/issuer`), so the previous check incorrectly stripped the `/issuer` prefix, generating a credential offer URI that CloudFront routed to S3 instead of the ALB → 403. Non-canonical deployments (custom domain, empty base-path) are unaffected.
- **OID4VCI — Verifier URL resolution**: `UrlResolverImpl.expectedVerifierBaseUrl()` now uses `TenantCustomDomainsLoader.findVerifierUrl()` (new `Optional`-returning method) when `X-Tenant` is present. If the loader has an entry for the tenant (non-canonical deployment), the configured verifier URL is returned; otherwise it falls back to `origin + verifierContextPath`. This avoids incorrectly deriving the verifier URL from the issuer origin on custom-domain deployments (e.g. `issuer.dome-marketplace-lcl.org/verifier` instead of the actual verifier domain).

### Changed (17-06-2026)
- Added custom domains registry to allow Issuer and Verifier URL for non-canonical deployments.
- **CORS**: Added CORS configuration to `bootstrapFilterChain` and registered `/w3c/**` and `/token/**` paths in `CorsConfig` to cover status list endpoints accessible by external wallets.

### Changed (15-06-2026)
- Removed duplicated `sub` JWT claim from W3C credentials, relying on `credentialSubject.id` as the subject identifier.
- **Tenant Resolution**: `TenantDomainWebFilter` now gives precedence to the `X-Tenant` header over the request host subdomain. If the header is absent, the tenant is resolved from the first host segment, using the effective forwarded host when `forward-headers-strategy: framework` is enabled. Environment suffixes such as `-stg`, `-dev` and `-pre` are stripped before the tenant registry lookup.
- Improved GDPR compliance by reducing PII logging.
- Upgraded `org.bouncycastle:bcprov-jdk18on` from `1.80` to `1.84` to address security advisories.
- Added Netty version override to `4.1.132.Final` to remediate CVE-2026-33870 affecting `netty-codec-http`.

### Fixed
- **Mail — kpmg template**: Remove unused `<style>` block with `@media` queries and `display: none` from `credential-offer-email-v2.html`. The CSS classes defined were never applied to any element (dead code), but the `display: none !important` rule was triggering corporate email filters (Exchange/Outlook) causing silent delivery failure. Fix has no visual impact. Also replace hardcoded event-specific header text (`Spring Meeting 2026` / `Encuentro de Primavera 2026`) with the generic `email.credential-offer.header` value.

### Added
- **Vintegris** Allow Vintegris signature

## [3.6.19] - 2026-06-09

### Fixed

- **OID4VCI — Holder Binding**: `cnf.jwk` and `credentialSubject.mandate.mandatee.id` now reference the same P-256 key pair. Previously `buildFromJwk()` assigned a random UUID as `subjectId`, so `mandatee.id` was pre-set to an arbitrary `did:key` from the portal form while `cnf.jwk` held the actual wallet key. Fixed by deriving `did:key` from the proof JWK (compressed EC point + P-256 multicodec varint `[0x80, 0x24]` + base58btc) and injecting it into `mandatee.id` at signing time. Affects all LEARCredentials with `mandate.mandatee` structure (`jwt_vc_json` and `dc+sd-jwt`) in both browser mode (Wallet PWA) and server mode (EBW).

## [3.6.18] - 2026-06-08

### Fixed
- **PBAC — Revocation**: `PolicyContext.hasPowerWithDomain` now uses case-insensitive domain comparison (`equalsIgnoreCase`) to match the behaviour of `PolicyContextFactory.resolveTenantAdmin`. A user with `Onboarding/Execute/domain=DOME` (uppercase in JWT) was rejected when the request `X-Tenant-Id` header arrived as `dome` (lowercase), causing an erroneous 401 on credential revocation despite holding the correct power.

## [3.6.17] - 2026-06-08

### Fixed
- **Mail**: Improve fallback alt text for blocked QR images

## [3.6.16] - 2026-05-28

### Fixed
- **Signature**: Validate key status for enabled and valid states

## [3.6.15] - 2026-05-26

### Fixed
- **Mail**: Fix default mail address

## [3.6.14] - 2026-05-22

### Fixed
- **Label Credential**: Fixed `subject` field showing empty in the credential procedure list — now correctly extracts the identifier from the end of the credential subject ID.

## [3.6.13] - 2026-05-21

### Changed

- **BBDD**: restore flyway migration for V1 and modify tenant_signing_config to V5

## [3.6.12] - 2026-05-19

### Changed

- **Signature**: add multiversion and multiprovider signature support

## [3.6.11] - 2026-05-19

### Fixed
- **Auth Endpoint:** Exposed `tenantType` in the `/api/v1/me` response payload by retrieving it from the tenant configuration service.

## [3.6.10] - 2026-05-18
### Added

- Centralized regex-based masking to prevent leakage of PII and secrets in logs.
- Direct delivery issuance: the credential is signed and returned immediately at issuance time.

### Changed

- The `delivery` parameter in the issuance request is expected to be a comma-separated string, e.g. `"email,direct"`.

### Fixed

- The `proof` parameter is no longer required by default; it is required only when cryptographic binding is requested.
- When mapping W3C credentials, `credentialSubject.id` is no longer overwritten if already present.
- UI QR credential offer now returns HTTPS wallet URL instead of openid-credential-offer://

## [3.6.9] - 2026-05-15

### Fixed
- Allow tenant admins to delegate onboarding when issuing credentials on behalf of a tenant in multi-organization setups.
- Fix organization ID extraction from the token when validating LEAR credential power delegation.

## [Unreleased]

### Added
- **CredentialProfile**: add `summary_claims`.

## [3.6.8] - 2026-05-13

### Added

- **Credential offer email**: Added knowledge base link to the credential offer email to help users access support resources.

## [3.6.7] - 2026-05-05

### Changed

- **Credential offer email v2**: Simplified steps assuming Wallet is already installed — removed download steps, replaced with open Wallet → scan QR with Wallet scanner → confirm. Removed "Open in Wallet" button section.
- **i18n**: Updated `step1-v2`, `step2-v2`, `step3-v2` keys and added `*-detail-v2` variants in `messages.properties` and `messages_es.properties`. Removed `step4-v2` and `wallet-hint-v2`.

## [3.6.6] - 2026-04-30

### Changed

- **Credential offer email v2**: Updated template.

## [3.6.5] - 2026-04-29

### Fixed

- Credential mandatorPath validation - Fixed organization path validation

## [3.6.4] - 2026-04-28

### Added

- **Credential offer email v2**: implemented tenant-specific email template rendering for the KPMG tenant.

## [3.6.3] - 2026-04-28

### Fixed

- **Credential offer double-send** — `GET /credential-offer/refresh/{token}` eliminado. El refresco de la oferta pasa ahora a una página Angular en el MFE (`credential-offer/refresh/:token`), evitando que los escáneres de email (ATP Safe Links) activen el reenvío al seguir el enlace automáticamente. El backend expone únicamente `POST /credential-offer/refresh/{token}` (JSON, sin Thymeleaf), con CORS habilitado para las llamadas cross-origin del MFE.
- **`buildRefreshUrl`** — la URL de refresco incluida en el email apunta ahora a `issuer.frontend_url` (MFE) en lugar de a la URL pública del backend.
- Eliminadas las plantillas Thymeleaf `credential-offer-refresh-*.html`, sustituidas por la página Angular.

## [3.6.2] - 2026-04-27

### Changed
- Refactored `CredentialOfferServiceImpl` and `EmailServiceImpl` to eliminate redundant URI building logic, centralizing wallet-specific URL formatting in the email adapter.

### Fixed
- Resolved `SyntaxError: Unexpected token '<'` in wallet frontedn. The `credential_offer_uri` now correctly points to the raw metadata JSON endpoint instead of the nested wallet UI URL.
- Improved email QR code compatibility. The QR code now uses an HTTPS deep link, allowing users to scan it directly with native mobile cameras instead of requiring the specific wallet app camera.

## [3.6.1] - 2026-04-27

### Changed

- Changed emails templates colours to match the new EUDIStack palette.
- **Refactor:** Migrated manual string manipulation in `buildWalletDeepLink` to a more robust approach using `UriComponentsBuilder`.

### Fixed
- Resolved `SyntaxError: Unexpected token '<'` in wallet frontedn. The `credential_offer_uri` now correctly points to the raw metadata JSON endpoint instead of the nested wallet UI URL.

## [3.6.0] - 2026-04-24

### Changed (EUDI-017 — URL resolution refactor)

Single source of truth for public and internal URLs. The 3.4.6..3.5.3
chain of patches (ISSUER_BASE_URL_CONTEXT_KEY → ServerWebExchange context
attribute → fields on DualTokenAuthentication) is collapsed into a clean
port + explicit-parameter design. Controllers resolve the public issuer
base URL from the live `ServerWebExchange` via `UrlResolver` and pass it
as an explicit parameter down the workflow / service chain. No domain
code reads URLs from config or from the Reactor context any more.

- **Added `UrlResolver` port** (`shared/domain/spi`) + implementation. Exposes:
  `publicIssuerBaseUrl(exchange)`, `publicOrigin(exchange)`,
  `expectedVerifierBaseUrl(exchange)`, `internalIssuerBaseUrl()`,
  `internalVerifierBaseUrl()`, `rewriteToInternalVerifier(publicUrl)`. The
  rewrite method preserves the URL path so that a verifier `jwks_uri` with
  the `/verifier` base-path is swapped to the intra-VPC origin without
  duplicating the prefix (regression covered by dedicated test).
- **Auth hot path** (`CustomAuthenticationManager`,
  `DualTokenAuthentication`, `DualTokenServerAuthenticationConverter`,
  `SecurityConfig`, `VerifierService(Impl)`): the converter captures the
  live `ServerWebExchange` into the auth token, the manager consumes it
  and asks `UrlResolver` for the expected `iss` values, doing exact-match
  against issuer and verifier URLs. No APP_URL / APP_VERIFIER_URL fallback.
  `VerifierService.verifyTokenSkippingIssuerCheck` removed — callers now
  pre-match iss unconditionally; the service validates signature + expiry only.
  `VerifierServiceImpl` composes the well-known URL with
  `UriComponentsBuilder` (path segments, never string concatenation), so
  the internal base-path is preserved even when endpoints start with a `/`.
- **Domain services** (`TokenService`, `AuthorizationServerMetadataService`,
  `AuthorizationService`, `CredentialOfferService`,
  `CredentialIssuerMetadataService`, `StatusListProvider`), **workflows**
  (`IssuanceWorkflow`, `Oid4VciCredentialWorkflow`, `HandleNotificationWorkflow`,
  `CredentialOfferRefreshWorkflow`, `Get{AuthorizationServer,CredentialIssuer}MetadataWorkflow`,
  `RevocationWorkflow`, `StatusListWorkflow`) and **controllers**
  (`Par`, `Token`, `Authorize`, `Credential`, `Notification`,
  `AuthorizationServerMetadata`, `CredentialIssuerMetadata`,
  `CredentialOfferRefresh`, `Issuance`, `Bootstrap`,
  `BitstringStatusList`): every method that needed the issuer base URL now
  receives it explicitly as `publicIssuerBaseUrl`; controllers inject
  `UrlResolver` and resolve from the exchange. ~30 files touched.

### Removed

- `AppConfig.getIssuerBackendUrl`, `getVerifierUrl`,
  `isIssuerBackendIssuer`, `isVerifierIssuer`, `baseOriginMatches`,
  `stripFirstLabel` — `iss` validation is exact-match now, via `UrlResolver`.
- `IssuerProperties.getIssuerBackendUrl`, `getVerifierUrl`,
  `isIssuerBackendIssuer`, `isVerifierIssuer`. The port only exposes
  internal URLs and non-URL settings.
- `AppProperties.url`, `verifierUrl` + `app.url` / `app.verifier-url` in
  `application.yml`. Public URLs are derived at runtime; no static config.
- `IssuerBaseUrlWebFilter` + `Constants.ISSUER_BASE_URL_CONTEXT_KEY` —
  the Reactor-context approach was never reliable under Spring Security
  (superseded in 3.5.1). Everything flows through `UrlResolver` now.
- `DualTokenAuthentication.requestBaseUrl` /
  `expectedVerifierBaseUrl` (replaced by a single `ServerWebExchange`
  field), `DualTokenServerAuthenticationConverter` constructor arg
  (`configuredContextPath`), `SecurityConfig` constructor arg,
  `VerifierService.verifyTokenSkippingIssuerCheck`,
  `CredentialIssuerMetadataServiceImpl.fallbackUrl`.

### Migration note

- Remove `APP_URL` and `APP_VERIFIER_URL` from every deployment (docker-
  compose, STG/PRO IaC, local dev). The issuer no longer reads them and
  startup will no longer fail if they are set, but they are dead weight.
- `APP_INTERNAL_URL` and `APP_VERIFIER_INTERNAL_URL` stay: they must
  include the service base-path (e.g.
  `http://verifier-core.stg.eudistack.local:8080/verifier`), already
  applied via IaC commit `003a114`.
- Local nginx (`eudistack-platform-dev/nginx/default.conf.template`)
  already sets `X-Forwarded-Proto` / `X-Forwarded-Host`, so the runtime
  URL derivation is consistent between local and STG.

## [3.5.3] - 2026-04-24

### Security (EUDI-094 post-cutover — verifier token validation decoupled from APP_VERIFIER_URL)

- **`DualTokenServerAuthenticationConverter`** now also captures the expected verifier base URL from the request origin (`${scheme}://${host}[:port]/verifier`). Under same-origin routing (Atlassian-style) the verifier lives on the same host as the issuer and signs tokens with `iss = ${origin}/verifier`. Passed through a new `DualTokenAuthentication.expectedVerifierBaseUrl` field.
- **`CustomAuthenticationManager.verifyAndParseJwtForIssuer`** gets a new exact-match branch for verifier tokens: when `iss` equals `expectedVerifierBaseUrl`, the token is accepted and the issuer check inside `VerifierService` is skipped (signature and expiration are still validated). `APP_VERIFIER_URL`-based fuzzy match remains as fallback for legacy/internal paths.
- **`VerifierService.verifyTokenSkippingIssuerCheck`** — new overload that validates signature and expiration but trusts the caller's pre-match of `iss`.
- Symptom before fix: login-driven calls to `/issuer/api/v1/me` (and other unified-chain endpoints) returned `401 Unknown token issuer` because `APP_VERIFIER_URL` still pointed to the legacy `login-stg.altia.eudistack.net` while tokens now carry `iss=https://sandbox-stg.eudistack.net/verifier`.

## [3.5.2] - 2026-04-24

### Changed (Issuer no longer owns `public` schema)

- **`V1__Public_schema.sql` eliminado** y directorio `src/main/resources/db/migration/` suprimido. `public.tenant_registry` deja de ser responsabilidad del Issuer; pasa a la plataforma (local: `init-databases.sh`, STG/PROD: `seed-tenants.*.sql`, futuro: microservicio de onboarding de tenants).
- **`TenantSchemaFlywayMigrator`**: eliminados `migratePublicSchema()` y su invocación. El Issuer solo lee `public.tenant_registry` para saber qué schemas `<tenant>_issuer` provisionar; no crea ni migra `public`. El log de cierre ya no menciona `public` (`Flyway multi-schema migration completed: N tenant schemas (suffix '_issuer')`).
- Si `public.tenant_registry` no existe aún al arranque, el Migrator loggea WARN y arranca con 0 tenants (comportamiento previo preservado).

### Migration note

En STG basta con `DROP TABLE public.flyway_schema_history;` antes del deploy de 3.5.2 (la tabla ya no la gestiona nadie y estorba si queda huérfana). `public.tenant_registry` y los schemas `<tenant>_issuer` quedan intactos; ningún dato de runtime se pierde.

## [3.5.1] - 2026-04-24

### Fixed (EUDI-094 post-cutover — final follow-up on 3.4.6/3.4.7)

- **`DualTokenServerAuthenticationConverter`** now captures the public base URL from the `ServerWebExchange` (mirrors `IssuerBaseUrlWebFilter.buildBaseUrl`) and passes it through the new `DualTokenAuthentication.requestBaseUrl` field. `CustomAuthenticationManager` reads the URL directly from the authentication object — no Reactor context indirection. This is what finally works: Spring Security's `AuthenticationWebFilter` runs the `ReactiveAuthenticationManager` in a scope where neither the `contextWrite`-populated `ISSUER_BASE_URL_CONTEXT_KEY` (3.4.6 attempt) nor the `ServerWebExchangeContextFilter` attribute (3.4.7 attempt) are visible. The only argument guaranteed to reach the manager is the `Authentication` built by the converter from the live `ServerWebExchange`.
- `SecurityConfig` wires the base path (`spring.webflux.base-path`) into the converter constructor so the converter can reconstruct the same URL the WebFilter emits for token issuance.

## [3.5.0] - 2026-04-24

### Changed (per-tenant schema naming — `<tenant>_issuer`)

- **`Constants.SCHEMA_SUFFIX = "_issuer"`** — constante nueva que el Issuer concatena al tenant id para resolver el schema físico en PostgreSQL. Evita colisiones del `flyway_schema_history` cuando varios servicios (issuer, verifier, ebw) comparten una misma base de datos.
- **`TenantAwareConnectionFactoryDecorator`** — `SET search_path TO <tenant>_issuer, public` (antes `<tenant>, public`). El `SYSTEM_TENANT` sigue usando solo `public`.
- **`TenantSchemaFlywayMigrator`** — lee el tenant id de `public.tenant_registry.schema_name` y concatena `SCHEMA_SUFFIX` antes de `CREATE SCHEMA IF NOT EXISTS` y `Flyway.configure().defaultSchema(...)`. Método `loadActiveTenantSchemas` renombrado a `loadActiveTenants`.
- **`V1__Public_schema.sql`** — eliminado el `INSERT` seed de `tenant_registry`. El onboarding de tenants no es responsabilidad del Issuer Flyway; pasa a `eudistack-platform-dev/postgres/seed-tenants*.sql` (hoy) y al futuro microservicio de onboarding.
- `tenant_registry.schema_name` sigue guardando el tenant id sin sufijo. Cada servicio concatena su propio sufijo en código.

### Migration note

STG se migró out-of-band con `rename-schemas-service-suffix.stg.sql` en `eudistack-platform-dev`: `ALTER SCHEMA platform|sandbox|dome|kpmg RENAME TO <name>_issuer` dentro de una transacción, sin tocar `tenant_registry`. Los `flyway_schema_history` viajan con el rename, por lo que el siguiente arranque del Issuer no reaplica migraciones `db/tenant`.

## [3.4.7] - 2026-04-24

### Fixed (EUDI-094 post-cutover — follow-up on 3.4.6)

- **`CustomAuthenticationManager`** now derives the public base URL directly from the `ServerWebExchange` (via `ServerWebExchangeContextFilter.EXCHANGE_CONTEXT_ATTRIBUTE`) instead of reading `ISSUER_BASE_URL_CONTEXT_KEY` from the Reactor context. In 3.4.6 the key was never visible: `IssuerBaseUrlWebFilter` writes it with `chain.filter(exchange).contextWrite(...)` which propagates **upstream only**, but Spring Security's `AuthenticationWebFilter` runs the `ReactiveAuthenticationManager` on a downstream branch — the key was still absent. The fallback to `APP_URL`-based fuzzy match kept firing and rejecting the token. Base URL is now built inline (scheme + host + port + `spring.webflux.base-path`) mirroring `IssuerBaseUrlWebFilter.buildBaseUrl`. Tests adapted to inject a `MockServerWebExchange` into the context.

## [3.4.6] - 2026-04-24

### Security (EUDI-094 post-cutover — token issuer validation decoupled from APP_URL) — superseded by 3.4.7

- **`CustomAuthenticationManager.verifyAndParseJwtForIssuer`** — when the request carries a `ISSUER_BASE_URL_CONTEXT_KEY` (populated by `IssuerBaseUrlWebFilter` from `exchange.getRequest().getURI()`), the method accepts the token only when `iss` matches the request public base URL exactly. This is both HAIP-aligned and stricter than the previous fuzzy `baseOriginMatches` against `APP_URL`, which failed after EUDI-094 (tokens issued with `iss=https://sandbox-stg.eudistack.net/issuer` were rejected because `APP_URL` still pointed to the legacy `issuer-stg.api.altia.eudistack.net`).
- **Fallback preserved**: when the Reactor context is absent (internal M2M paths, unit tests), the original `APP_URL`-based fuzzy match still runs. No behavioural change for tests; no invalidation of in-flight tokens.
- Added unit tests: exact-match acceptance bypasses `AppConfig`, and mismatch falls back to the APP_URL path.
- Follow-up: EUDI-017 will drop `APP_URL` entirely (see memory `project_issuer_app_url_deprecation`).

## [3.4.5] - 2026-04-23

### Changed

- **`application.yml`**: `server.forward-headers-strategy` default changed from `none` to `framework`. Every deployed environment (local nginx, AWS ALB+CloudFront) runs the issuer behind a trusted proxy, so the previous default forced each environment to inject `SERVER_FORWARD_HEADERS_STRATEGY=framework` or suffer silent breakage — most visibly, `/issuer/health` returning `401` in STG because Spring Security evaluated the matcher against the raw `/issuer/health` path before the base-path was stripped. Override to `none` only for jar-standalone scenarios (unit tests, direct `java -jar` without proxy). Aligns with the verifier, which already hardcodes `framework`.

## [3.4.4] - 2026-04-23

### Fixed

- **`TenantDomainWebFilter`**: whitelist now covers subpaths of `/health` and `/prometheus` (e.g. `/health/liveness`, `/health/readiness`). Actuator probes that hit the container with a host that does not resolve to a tenant (ALB target-group health check, Docker healthcheck, `curl localhost`) no longer fail with `404 TENANT_NOT_FOUND`.
- **`SmtpHealthIndicator`**: select the `smtps` transport when `mail.smtp.ssl.enable=true` or the port is `465`. The previous hard-coded `"smtp"` transport hung the socket against implicit-TLS endpoints (AWS SES `:465`) until timeout, which tumbled the aggregate `/health` into `DOWN`.
- **`VerifierHealthIndicator`**: probe `/verifier/health` instead of `/.well-known/openid-configuration`. The verifier mounts all endpoints under its own `/verifier` base-path, so the previous URL returned `404` and forced the component to `DOWN` in every environment.
- **`application.yml`**: declare explicit `liveness` and `readiness` health groups restricted to `livenessState` / `readinessState`. External dependencies (`smtp`, `verifier`) remain visible in the aggregate `/health` for observability, but their transient failure no longer takes the pod out of the ALB pool — as long as the ALB target-group probe points at `/issuer/health/liveness` (or `/readiness`).

## [3.4.3] - 2026-04-23

### Fixed

- **`TenantDomainWebFilter`**: strip known environment suffixes (`-stg`, `-dev`, `-pre`) from the tenant identifier before the `tenant_registry` lookup. Non-prod DNS follows the `{tenant}-{env}.eudistack.net` pattern (e.g. `sandbox-stg.eudistack.net`), so the filter previously returned `404 TENANT_NOT_FOUND` when resolving `sandbox-stg` against a registry that only contains `sandbox`. The strip runs after the `TENANT_NAME_PATTERN` validation and covers both the `X-Tenant-Id` header and the host-derived path. Tenant schemas remain environment-agnostic across local/stg/pre/pro.

## [3.4.2] - 2026-04-22

### Fixed

- **Issuer startup on STG**: disabled Spring Boot's auto-configured `flywayInitializer` (`spring.flyway.enabled: false`) in `application.yml`. The auto-config was attempting a JDBC connection without user/password (only `SPRING_FLYWAY_URL` is injected in ECS), causing `SCRAM-based authentication, but no password was provided` and aborting context startup. `TenantSchemaFlywayMigrator` continues to run migrations for `public` + all tenant schemas using R2DBC credentials.

## [3.4.1] - 2026-04-22

### Changed (EUDI-065 — `APP_MAIL_FROM` per-tenant)

- **`EmailServiceImpl`** now resolves the transactional email sender via `TenantConfigService.getStringOrThrow("issuer.mail_from")` inside each public method, so every tenant can send from its own address once SES has it verified. Public `EmailService` API unchanged.
- **`app.mail-from`** removed from `application.yml`; **`APP_MAIL_FROM`** removed from `docker/docker-compose.yml`.
- **Flyway V3 per-tenant migration** (`V3__Seed_mail_from_placeholder.sql`) seeds a `issuer.mail_from` placeholder so existing environments don't fail on `getStringOrThrow` before the real seed runs.
- **`EmailServiceImpl.sendTxCodeNotification`** now logs the original exception before mapping to `EmailCommunicationException` (the previous `onErrorMap` lambda swallowed the cause).

### Tests

- Updated `EmailServiceImplTest` to inject a mocked `TenantConfigService` returning the test mail_from.
- Sibling change in `eudistack-platform-dev`: `seed-tenants[.stg].sql` seeds `issuer.mail_from` for all 4 tenants (`noreply@mail-stg.eudistack.net`).

## [3.4.0] - 2026-04-22

### Changed (EUDI-025 US-09 — QTSP signing 100% per-tenant)

**BREAKING (internal contract):** all QTSP signing paths read configuration exclusively from `tenant_signing_config`; no global fallback. A tenant without a row in that table fails only its own signing operations, isolated from the rest.

- **`SigningRequest` extended** with `remoteSignature: RemoteSignatureDto`. `DelegatingSigningProvider` resolves the tenant's QTSP config via `TenantSigningConfigService.getRemoteSignature()` and injects it into the request before delegating to the concrete CSC provider.
- **`QtspAuthClient`, `QtspSignHashPort` + `QtspSignHashClient`, `QtspIssuerService` + impl, `RemoteSignatureServiceImpl`, `JwsSignHashService` + impl** now take `RemoteSignatureDto` (directly or via `SigningRequest`) instead of reading a global bean. `QtspIssuerService.getCredentialId()` removed — callers use `cfg.credentialId()` directly.
- **`IssuerFactory`** (StatusList) now resolves the tenant's QTSP config from `TenantSigningConfigService` and passes it to `qtspIssuerService.resolveRemoteDetailedIssuer(cfg)`. If the tenant has no signing config, fails fast with `SigningException`.
- **`DelegatingSigningProvider`** throws `SigningException` when `tenant_signing_config` is empty for the current tenant.
- **`TenantSigningConfigService`**: removed `getProvider()` and the global fallback in `getRemoteSignature()`. Returns `Mono.empty()` when the tenant has no row.

### Removed

- **`RuntimeSigningConfig`** bean + **`SigningRuntimeConfigProperties`** + **`RemoteSignatureProperties`** + **`SigningRuntimeConfigController`** + **`SigningConfigPushRequest`** DTO + test.
- **`PUT /internal/signing/config`** and **`GET /internal/signing/provider`** endpoints — per-tenant config is seeded via SQL or (future) a dedicated config management service.
- **`@ConditionalOnProperty(issuer.signing.runtime.enabled)`** from `SigningProviderConfig` — the signing module is always wired.
- **`signing.runtime.*`** and **`signing.remote-signature.*`** blocks from `application.yml`.
- **`SIGNING_RUNTIME_ENABLED`, `SIGNING_RUNTIME_CONTROLLER_ENABLED`, `SIGNING_DEFAULT_PROVIDER`, `SIGNING_REMOTE_*`** env vars from `docker/docker-compose.yml`.
- **`SIGNING_PROVIDERS_PATH`, `SIGNING_CONFIG_PATH`** constants from `EndpointsConstants` + their entries in `SecurityConfig`. Related tests removed from `SecurityConfigTest`.

### Changed (health indicator)

- **`SigningServiceHealthIndicator`** simplified — signing is per-tenant, so the global up/down no longer depends on a shared config. Reports `mode=per-tenant`.

### Tests

- Updated: `DelegatingSigningProviderTest`, `QtspAuthClientTest`, `QtspSignHashClientTest`, `QtspIssuerServiceImplTest`, `RemoteSignatureServiceImplTest`, `CscSignHashSigningProviderTest`, `CscSignDocSigningProviderTest`, `JwsSignHashServiceImplTest`, `SigningProviderConfigTest`, `IssuerFactoryTest`. All 765 tests pass.
- Sibling change in `eudistack-platform-dev`: `seed-tenants[.stg].sql` seeds `tenant_signing_config` for all 4 tenants with mock-qtsp (local and STG both have mock-qtsp reachable).

## [3.3.1] - 2026-04-22

### Removed (compose/env cleanup — no breaking at runtime)

- **Dead config keys** removed from `AppProperties`, `AppConfig`, `IssuerProperties`, `application.yml` and `docker/docker-compose.yml`:
  - `app.issuer-frontend-url` / `APP_ISSUER_FRONTEND_URL` — no runtime consumers (only referenced in `cors-origins.yaml` comments and tests).
  - `app.wallet-url` / `APP_WALLET_URL` / `getWalletFrontendUrl()` — replaced by `tenant_config.issuer.wallet_url` (read via `TenantConfigService.getStringOrThrow`).
  - `app.knowledge-base.*` / `APP_KNOWLEDGE_BASE_*` + record `AppProperties.KnowledgeBase` — never consumed by the backend (the MFE reads `theme.json#content.knowledgeBaseUrl` per tenant).
  - `APP_CONFIG_SOURCE` — never read (was declared only in docker-compose).
  - `ISSUER_IDENTITY_JWT_CREDENTIAL` — already documented as dead code.

### Changed (EUDI-065 Fase 8 — per-tenant wallet URL enforcement)

- **`CredentialOfferServiceImpl.buildCredentialOfferUri`** now resolves `issuer.wallet_url` per-tenant via `tenantConfigService.getStringOrThrow` (no global fallback). The method signature returns `Mono<String>` for the email channel — required to chain the async config lookup. Matches the pattern already applied to `admin_organization_id` in 3.3.0.

## [3.3.0] - 2026-04-21

### Added (EUDI-065 Fase 8 / EUDI-025 US-08)

- **`GET /api/v1/me`** (`MeController` + `MeResponse` DTO). Resuelve el rol del caller contra el tenant actual usando `AccessTokenService.getAuthorizationContext` y lo expone al frontend. Registrado en `SecurityConfig.unifiedFilterChain` como endpoint autenticado. Unit tests: `MeControllerTest` (happy path TenantAdmin en KPMG, SysAdmin read-only en platform).
- **`TenantConfigService.getStringOrThrow(key)`** + **`TenantConfigMissingException`** para claves requeridas por tenant. Si la clave no está seeded, falla solo el tenant afectado (los demás siguen operativos).
- **`TenantDomainWebFilter`** bypass para `/health` y `/prometheus` (evita warnings "Tenant '127' not found" de probes que pegan al IP del contenedor).

### Changed (breaking — internal)

- **`admin_organization_id` sin fallback global.** Eliminados `AppProperties.adminOrganizationId`, `AppConfig.getAdminOrganizationId()`, `IssuerProperties.getAdminOrganizationId()` y la línea `admin-organization-id: ${APP_ADMIN_ORGANIZATION_ID:...}` de `application.yml`. `APP_ADMIN_ORGANIZATION_ID` eliminada también del docker-compose del repo. `AccessTokenServiceImpl.resolveRole` y `PolicyContextFactory.resolveTenantAdmin` ahora usan `getStringOrThrow`. Rationale: el fallback enmascaraba tenants sin seed (p.ej. KPMG con `VATES-A78446333`). Tests afectados (`PolicyContextFactoryTest`, `AccessTokenServiceImplTest`, `AppConfigTest`, `IssuanceServiceImplTest`, `IssuancePdpServiceImplIntegrationTest`) actualizados para mockear `getStringOrThrow`.
- **`V1__Tenant_schema.sql`** ya no inserta `admin_organization_id = VATES-A15456585`. Cada tenant lo recibe per-tenant desde `seed-tenants[.stg].sql` (platform/sandbox/dome → Altia; kpmg → `VATES-A78446333`).
- **`V1__Public_schema.sql`** — display_name de `sandbox` → `"EUDIStack Sandbox"`.
- **Bootstrap API: contrato unificado con `X-Tenant-Id`.** El campo `tenant` del body `BootstrapRequest` se elimina; el tenant pasa por header (mismo convenio que el resto de la API). `TenantDomainWebFilter` ya no bypasea `/api/v1/bootstrap` — valida tenant y escribe el Reactor context. `BootstrapController` lee del context y ya no depende de `TenantRegistryService` (delega validación al filter). `BootstrapControllerTest` reescrito (4 tests); `TenantDomainWebFilterTest` incluye casos bootstrap con `X-Tenant-Id` válido/malformado.

### Migration

- Ejecutar `make reset && make up && make seed-tenants && make seed-verify` en local. El checksum mismatch de Flyway por editar `V1` requiere reset de volúmenes (aceptable antes del primer despliegue AWS).
- Scripts `seed-local-sd.py`, `seed-local-w3c.py`, `seed-local-sd-aws-stg.py`, `seed-ovh.py` actualizados para enviar `X-Tenant-Id` header y omitir el campo `tenant` del body.

## [3.2.2] - 2026-04-21

### Changed (EUDISTACK-166 / EUDI-064: unify tenant header name)

- **Breaking for internal callers.** Renamed the multi-tenancy header from `X-Tenant-Domain` to `X-Tenant-Id`.
  - `Constants.TENANT_DOMAIN_HEADER` → `Constants.TENANT_ID_HEADER` (value `"X-Tenant-Id"`).
  - `TenantDomainWebFilter` now reads `X-Tenant-Id` as the sole tenant header (Host header remains the fallback).
  - `RequireTenantMatchRule` error message and Javadoc updated.
  - Rationale: align with EUDI-064 US-01 (API Gateway route), prepare for AWS internal DNS going tenant-agnostic (Cloud Map namespace `{env}.eudistack.local`), and match the standard API Gateway convention. Decision taken with infra on 2026-04-21.
  - Callers that set the header explicitly (e.g. local dev via nginx, service-to-service clients) must update to `X-Tenant-Id`. No behaviour change when the tenant is resolved from the Host header.

## [3.2.1] - 2026-04-21

### Fixed (EUDI-065: cross-tenant TenantAdmin bypass)

- **`PolicyContextFactory.resolveTenantAdmin`** now validates that an `Onboarding/Execute` power's `domain` matches the current `tenantDomain` (case-insensitive). Previously the check only compared `function` + `action`, so a KPMG-issued credential (power domain = KPMG) was promoted to TenantAdmin when logging in on the DOME tenant, granting full Credential Manager access cross-tenant. Fixes the behaviour described in EUDI-065 §1.2 that was not enforced in the login PDP. Added unit tests covering the KPMG→DOME rejection and the case-insensitive accept.

## [3.2.0] - 2026-04-21

### Changed (EUDI-065: Unified LEAR issuance rule)

- **`RequireLearCredentialIssuanceRule`** replaces the OR-combined
  `RequireSignerIssuanceRule` + `RequireMandatorDelegationRule`. A single
  rule now covers `LEARCredentialEmployee` and `LEARCredentialMachine`
  issuance with three clauses: power base (`Onboarding/Execute`),
  escalation prevention (payload cannot delegate `Onboarding/Execute` nor
  `Certification/Attest`), and org scope (same-org or on-behalf — the
  latter only for TenantAdmin in `multi_org` tenants). SysAdmin keeps the
  full bypass.
- **`ProductOffering` removed as issuance gate.** It remains a valid
  delegable power that can appear in emitted credentials. The
  `delegation_function` field in `issuance_policy` is no longer read.
- **`PolicyContext.tenantType`** added (`simple` | `multi_org` |
  `platform`); `TenantRegistryService.getTenantType()` resolves it from
  `public.tenant_registry`.
- **`IssuancePdpServiceImpl`** dispatcher simplified: each profile now
  declares exactly one rule name. `PolicyEnforcer` OR-combination is no
  longer used for issuance.

See **ADR-002** (`docs/_shared/architecture/adr/adr-002-pdp-issuance-rules.md`
in `eudistack-platform-dev`) for rationale and full rule semantics.

### Removed (EUDI-065)

- `RequireSignerIssuanceRule` + its test — semantics folded into the
  unified rule with SysAdmin bypass.
- `RequireMandatorDelegationRule` — superseded by the org-scope clause
  of the unified rule.

## [3.1.0] - 2026-04-20

### Changed (EUDI-064: bootstrap is now cross-tenant)

- `POST /api/v1/bootstrap` requires a top-level `tenant` field in the
  request body. The bootstrap flow is administrative and
  cross-tenant: the caller declares the destination tenant explicitly
  instead of relying on hostname or `X-Tenant-Domain` header.
  `TenantDomainWebFilter` now bypasses `/api/v1/bootstrap`. Breaking
  change for direct callers; all in-tree scripts are updated in the
  `eudistack-platform-dev` repo in a sibling commit.

### Added (EUDI-065: Three-role authorization model)

- **`UserRole` enum and `AuthorizationContext` record** replacing `OrgContext` with explicit role (SYSADMIN, TENANT_ADMIN, LEAR) and `readOnly` flag.
- **SysAdmin detection via power** `organization/EUDISTACK/System/Administration` (no longer via `orgId == ADMIN_ORGANIZATION_ID`).
- **Platform tenant read-only view** — SysAdmin operating from `platform` tenant sees cross-tenant issuances with `tenant` field in DTO but cannot create/revoke/withdraw.
- **SysAdmin ↔ TenantAdmin equivalence** outside `platform` — from any other tenant, SysAdmin has same permissions as TenantAdmin (can write).
- **TenantAdmin role** — `organizationId == tenant.admin_organization_id` + domain power. Sees all issuances of the tenant, can create "on behalf", withdraw, revoke.
- **`admin_organization_id` per-tenant** in `tenant_config` table (seeded via Flyway V1).
- **`RequireOrganizationRule` bypass for TenantAdmin** — in addition to SysAdmin.
- **Withdraw authorization** — `canWrite()` check for platform tenant; ownership check for LEAR (only own org).
- **Flyway migration consolidation** — V1+V2+V3 merged into single `V1__Tenant_schema.sql` with `admin_organization_id` seed.

### Fixed (EUDI-064: AWS deployment readiness)

- **`TenantDomainWebFilter` hostname fallback** — When `X-Tenant-Domain` header is absent (AWS CloudFront + ALB path, no nginx to inject it), the tenant is now extracted from the first subdomain segment of the request host (e.g. `kpmg.eudistack.net` → `kpmg`). Header wins when both are present. Malformed identifiers return 400; unknown tenants continue to return 404; requests without a usable host still pass through for healthchecks. `RequireTenantMatchRule` error message updated accordingly.
- **`spring.webflux.base-path` re-enabled** (default `/issuer`, env `APP_CONTEXT_PATH`). Spring now mounts all WebFlux handlers under `/issuer` and `IssuerBaseUrlWebFilter` reads the same property to build public URLs — single source of truth. The previous R2DBC context-propagation regression is no longer reproducible; `reactor.context-propagation: auto` is sufficient. Unblocks AWS ALB + CloudFront deployments that do not inject `X-Forwarded-Prefix` and also removes the dependency on nginx prefix-strip in local dev.
- **MDC propagation across Reactor operators** — `tenantDomain` is now bridged from the Reactor subscriber context to SLF4J MDC via `Hooks.enableAutomaticContextPropagation()` plus a `ThreadLocalAccessor` registered in `MdcContextConfig`. The logback pattern `%X{tenantDomain:-}` now renders the tenant on every log line inside a reactive chain.

### Fixed (EUDI-064: Multi-tenant URL resolution)

- **`IssuerBaseUrlWebFilter`** reads context path from `ForwardedHeaderTransformer` instead of `X-Forwarded-Prefix` header (Spring WebFlux strips forwarded headers after processing).
- **`ParController` / `TokenController`** use `pathWithinApplication()` to avoid double `/issuer/issuer/` prefix in DPoP `htu` validation.

### Deprecated

- **`ADMIN_ORGANIZATION_ID` global env var** — Replaced by `tenant_config.admin_organization_id` per-tenant. Kept as fallback during migration.

### Changed

- **EUDI-013:** Migrate W3C credential JWT encoding to VCDM v2.0 (VC-JOSE-COSE)
  - Remove `vc` wrapper from JWT payload — credential properties are now root JWT claims
  - Set JOSE header `typ: vc+jwt` for W3C credentials and BitstringStatusListCredential
  - Remove duplicate JWT registered claims (`jti`, `sub`, `nbf`) from W3C credential payload
  - Rename credential_configuration_id: `learcredential.employee.w3c.1` → `.w3c.4`, `learcredential.machine.w3c.1` → `.w3c.3`
- **Actuator config migrated to Spring Boot 3.5 `access` API** — Replace deprecated `enabled-by-default: false` / `enabled: true` with `access: none` / `access: unrestricted`. No behavioral change.
- **IssuerFactory always remote** — Issuer identity is now always resolved from the QTSP via `credentials/info`, removing dependency on local certificate. (EUDI-023)
- **Credential offer email copy updated** — Update credential offer email copy in English and Spanish, remove the footer, and add a helper message above the wallet button.
- **Credential Offer Delivery**: Refactored the `CredentialOfferService` to support nested URL structures for the email delivery channel.
- **URL Encoding**: Implemented double URL encoding for the `credential_offer_uri` parameter to ensure that deep links are correctly preserved through the Wallet's authentication guards.
- **Protocol Standardization**: Updated the query parameter name from `credential_ofer_uri` to the OIDC standard `credential_offer_uri`.

### Added

- **Per-tenant CORS origins registry** — CORS allowed origins are now loaded from an external `cors-origins.yaml` file (configurable via `APP_CORS_ORIGINS_PATH`) and merged with the base origins (`APP_ISSUER_FRONTEND_URL`, `APP_WALLET_URL`). Supports multi-tenant deployments where each tenant has distinct frontend domains.
- **QTSP remote signing as default** — Default signing provider is now `altia-mock-qtsp` at `https://mock-qtsp.altia.fikua.com` via CSC API v2. Configuration loaded from `signing.remote-signature.*` in `application.yml` with env var overrides (`SIGNING_REMOTE_*`). (EUDI-023)
- **`signingOperation` config per QTSP** — Each QTSP declares whether it uses `sign-hash` or `sign-doc`. DelegatingSigningProvider routes by this field. No implicit fallbacks. (EUDI-023)
- **`RemoteSignatureProperties` / `SigningRuntimeConfigProperties`** — New `@ConfigurationProperties` records for default QTSP config from YAML. (EUDI-023)
- **Email notification on consent timeout** — Send an email notification when user consent times out during issuance.
- **SD-JWT mandate wrapper with nested disclosures** — SD-JWT credentials emit mandatee/mandator/power inside a `mandate` wrapper with `_sd` digests at the nested level. (EUDI-012)
- **RSA algorithm support in JAdES header** — RS256/384/512 and PS256 OIDs mapped for QTSPs with RSA certificates. (EUDI-023)

### Fixed

- **Signing algorithm hardcoded to ES256** — `JwsSignHashServiceImpl` now receives the signing algorithm OID from the QTSP certificate instead of hardcoding ES256. Fixes Status List Credentials signed with RSA certificates.
- **SD-JWT email delivery NPE** — Organization extraction for email notifications used hardcoded path `credential.get("mandator")` which doesn't exist in SD-JWT structure. Now reads `policy_extraction.mandator_path` from the credential profile dynamically.
- **Email error logging** — Added `doOnError` logging in `CredentialOfferServiceImpl` to surface the root cause of email failures instead of swallowing exceptions.
- **W3C issuer.id removed during credential build** — `GenericCredentialBuilder` was stripping the `id` field from the issuer object, causing Verifier schema validation failure (`required property 'id' not found`).
- **DPoP htu mismatch behind ALB** — PAR and Token controllers now derive the DPoP `htu` URI from the `IssuerBaseUrlWebFilter` context (which resolves `https://` correctly) instead of `exchange.getRequest().getURI()` (which returns `http://` behind an ALB that terminates TLS).

### Removed

- **Unused dependencies removed** — The following dependencies were removed from `build.gradle` as they are no longer needed:
  - `com.fasterxml.jackson.core:jackson-databind`
  - `com.fasterxml.jackson.datatype:jackson-datatype-jsr310`
  - `com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.17.2`
  - `io.micrometer:context-propagation`
  - `org.mockito:mockito-inline:5.2.0` (test)
  - `com.squareup.okhttp3:mockwebserver:4.12.0` (test)

- **`ISSUER_IDENTITY_JWT_CREDENTIAL` property** — Dead code. LEARCredentialMachine JWT for trust framework registration is no longer consumed. Identity is now managed via `privateKey` + `didKey` + X.509 certificate.
- **`InMemorySigningProvider`** — Local certificate-based signing removed. All signing is now via remote QTSP. (EUDI-023)
- **`DefaultSignerConfig` / `SignerConfig`** — Signer identity extracted from local cert no longer needed. (EUDI-023)
- **DSS legacy flow** — `getSignedDocumentDSS`, `signPath`, `type="server"`, `SIGNATURE_REMOTE_TYPE_SERVER` removed. (EUDI-023)
- **`SIGNING_CERTIFICATE_CERT_PATH` / `SIGNING_CERTIFICATE_KEY_PATH`** — Local certificate env vars removed. Use `SIGNING_REMOTE_*` instead. (EUDI-023)

## [3.0.0] - 2026-03-24

### Added

- **Dynamic URL resolution for multi-tenant deployment** — `IssuerBaseUrlWebFilter` extracts the public base URL from `X-Forwarded-*` headers and stores it in Reactor context. Metadata, credential offers, status list URLs, and token endpoints now derive URLs from the request instead of static `APP_URL`. Enables true multi-tenant with per-tenant subdomains. (EUDI-017)
- **ADOT Java Agent for CloudWatch X-Ray tracing** — Dockerfile includes AWS OpenTelemetry agent, activated via `JAVA_TOOL_OPTIONS`.
- **Reusable bootstrap token** — Bootstrap token can be reused for demo integrations instead of being single-use.
- **Dependabot config and PR template** — Automated dependency updates and standardized PR format.

### Fixed

- **Tenant validation uses `tenant` claim instead of `organizationIdentifier`** — `RequireTenantMatchRule` now compares the `tenant` claim (injected by the Verifier from OIDC client config) against the `X-Tenant-Domain` header (injected by nginx). Previously compared `mandator.organizationIdentifier`, conflating tenant and organization. B2B2C model: tenant groups organizations, organization groups users. `PolicyContext` gains `tokenTenant` field; `PolicyContextFactory` extracts the `tenant` claim. (EUDI-017)
- **Token issuer check order in `CustomAuthenticationManager`** — Check own issuer before verifier (`isIssuerBackendIssuer` before `isVerifierIssuer`) to avoid false match when both share the same base origin (subdomain routing on same port).
- **WIA PoP aud validation** — Resolves audience dynamically from `X-Forwarded-Host` instead of static `APP_URL`. (EUDI-017)
- **`RateLimitFilter` NPE with `ForwardedHeaderTransformer`** — Handle `getAddress() == null` on unresolved `InetSocketAddress` created by Spring's `ForwardedHeaderTransformer`. Uses `getHostString()` as fallback.

### Changed

- Refactor email templates: replace 6 per-language HTML files with 3 unified Thymeleaf i18n templates using locale-based resolution.
- Modernize email template design with consistent table-based layout, inline styles, and unified color scheme.
- Update EmailServiceImpl to use locale-aware Thymeleaf context instead of language-suffix template names.
- Clean up messages.properties: remove orphaned keys and add new i18n keys for all email templates.
- Restricted CORS allowed origins to prevent unauthorized cross-origin requests (SEC-001).
- Refactored CorsConfig to use AppConfig for dynamic origin loading.

## [v2.2.21](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.21)
### Added
- Add handling for missing exceptions in "GlobalExceptionHandler".
- Add tests for the new exception handling.

## [v2.2.20](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.20)
### Added
- Add support for sign hash implementation.
- Add configuration signing endpoint.

## [v2.2.19](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.19)
### Added
- Add support for sign hash implementation.
- Add configuration signing endpoint.

## [v2.2.18](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.18)
### Changed
- Add cnf to the credential.
- Add CORS public permissions for vci issuances paths.

## [v2.2.17](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.17)
### Added
- Add support for multiple signing keys in the SPI implementation.
- Add configuration properties to specify the signing key alias and credentials.

## [v2.2.16](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.16)
### Added
- SPI interface for credential signing.
- Baseline SPI implementation for local and remote signing.

### Changed
- Refactoring of the signing logic to utilize the SPI


## [v2.2.15](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.15)
### Changed
- Updated Java and Spring Boot version.

## [v2.2.14](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.14)
### Changed
- Updated project-name.

## [v2.2.13](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.13)
### Changed
- Create bitstring-encoded lists using MSB-first ordering.

## [v2.2.12](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.12)
### Changed
- Update Failure case in Notification Endpoint.

## [v2.2.10](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.10)
### Fixed
- Don't send mail when Deferred Credential fails.

## [v2.2.9](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.9)
### Added
- Notification Endpoint implemented

## [v2.2.8](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.8)
### Changed
- Update refresh token.
- Update deferred credential flow.

## [v2.2.7](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.7)
### Added
- Cryptographic Binding implemented

## [v2.2.6](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.6)
### Changed
- Set vault's secret mounts as environment variable.
- Remove 'actuator/' path from health and prometheus base path.

## [v2.2.5](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.5)
### Fixed
- LEARCredentials mandator validation by OrgId.

## [v2.2.4](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.4)
### Added
- LEARCredentialMachine async signature.

## [v2.2.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.3)
### Fixed
- Prevent retrying the signature process when the credential procedure is not in PEND_SIGNATURE status.

## [v2.2.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.2)
### Changed
- Add org ID validation for notification and async signature flows.

## [v2.2.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.1)
### Added
- Add environment variable `sys-admin`, use it instead of constant DEFAULT_ORGANIZATION_NAME, which was used in email templates.

## [v2.2.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.2.0)
### Added
- Make admin organization identifier configurable (add adminOrganizationId env variable).
- When fetching procedures, if the authenticated user is an admin, fetch across all organizations.
- When fetching a procedure, if the authenticated user is an admin, don't restrict by organization.
- Enable R2DBC auditing to auto-populate `created_at`, `updated_at`, `created_by`, and `updated_by`.
- Resolve auditing principal from the JWT access token (prefer ID token when available).

### Changed
- For Employee and Machine credentials, set the `organization_identifier` field with the mandator email.
- `updated_at` in `CredentialProcedure` and related entities is now managed automatically by Spring Data (no manual updates).
- `subject_email` in `CredentialProcedure` and related entities has been renamed to `email`.
- In "activate credential" email Spanish template, replace "Estimado/a ," by "Hola,"

### Fixed
- Change deprecated build image openjdk:17-alpine by eclipse-temurin:17-jdk-alpine
- Send signature failure emails to the authenticated requester’s email, not the credential mandator’s updated email.

### Removed
- Sign controller (unused).

## [v2.1.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.1.1)
### Added
- Get default language from configuration, use it to translate messages (emails, PIN description).

## [v2.1.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.1.0)
### Changed
- If LEARCredentialMachine issuance presubmitted data contains credential_owner_email, use it as owner email.
- Don't include name in emails.

### Fixed
- When sending Label Credential to VC URI, send it encoded.

## [v2.0.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v2.0.0)
### Added
- Label credential issuance.
- LEARCredentialMachine issuance.
- Sign access request.
- Revocation endpoint.
- Revoke and expired credential notification.
- Handle error when sending PIN and when serializing credential.
- Handle errors in security chains flow.

### Changed
- Adapt endpoints to oid4vci.
- Refactor SecurityConfig credential issuer filters.
- Standardize error handling to RFC 7807 across all endpoints.
- Move GlobalExceptionHandler to shared module and add specific ControllerAdvice for each domain.
- Remove unused exceptions.



## [v1.7.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.7.0)
### Added
- Added remote signature configuration.

## [v1.6.9](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.9)
### Fixed
- Store Verifiable certification metadata after issuance
- Send Verifiable certification to responseUri after remote signature
- Modify the message sent after successful remote signature; adapt it to Verifiable Certification

## [v1.6.8](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.8)
### Fixed
- Error on credential request contract.

## [v1.6.7](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.7)
### Fixed
- When updating transaction code, delete previous one

## [v1.6.6](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.6)
### Fixed
- OID4VCI cors configuration.

## [v1.6.5](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.5)
### Fixed
- Refactor configs.

## [v1.6.4](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.4)
### Feature
- Migrate from Keycloak extension.

## [v1.6.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.3)
### Fixed
- Problem with public cors configuration.

## [v1.6.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.2)
### Fixed
- Separate internal and external issuing endpoints to be able to apply different authentication filters.
- Use M2M token when issuing Verifiable Certifications.

## [v1.6.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.1)
### Fixed
- Handle error during mail sending on the credential offer.

## [v1.6.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.6.0)
### Changed
- Added role claim and validations.
- Modified authenticator to allow access exclusively with the "LEAR" role, returning a 401 error for any other role.

## [v1.5.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.5.2)
### Fixed
- Fixed parsing learCredentialEmployee

## [v1.5.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.5.1)
### Fixed
- Fixed parsing certificates

## [v1.5.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.5.0)
### Added
- Added support to sign the credential with an external service.
- Now issuer is created with data from the external service.
- Error handling for the external service flows.
- Added controller to handle manual signature after failed attempts.

## [v1.4.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.4.3)
### Fixed
- Solve error on schema importation for flyway migration.

## [v1.4.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.4.1)
### Fixed
- Solve error during credential serialization.

## [v1.4.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.4.0)
### Added
- Compatibility with LEARCredentialMachine to issue LEARCredentialEmployee.

## [v1.3.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.3.0)
### Changed
- The issuer now issues only LearCredentialEmployee v2.

## [v1.2.5](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.5)
### Changed
- Changing environment variable for wallet knowledge redirection to email.
- Changed email template implementation for better compatibility.

## [v1.2.4](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.4)
### Changed
- Fix a problem with a cors endpoint.

## [v1.2.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.3)
### Added
- Add cors configuration for externals clients on the issuance endpoint.

### Changed
- Change email template styles, improve compatibility accross different email providers (e.g., Gmail)


## [v1.2.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.2)
### Added
- Add scheduled task to set EXPIRED status to credentials that have expired.

## [v1.2.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.1)
### Added
- Add support for requesting a fresh QR code if the previous one has expired or was an error during the proccess of

## [v1.2.0](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.2.0)
### Added
- Validation of authentication for issuance against the verifier.
- Verifiable Certifications issuance and sending to response_uri.
### Changed
- List credentials in order from newest to oldest.

## [v1.1.3](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.1.3)
### Changed
- Change the Credential Offer email template

## [v1.1.2](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.1.2)
### Changed
- Change the order of the received email from the pin during the issuance of a credential.

## [v1.1.1](https://github.com/in2workspace/in2-issuer-api/releases/tag/v1.1.1)
### Fixed
- Fixed LEARCredentialEmployee data model. Implement W3C DATA model v2.0 (validFrom, validUntil). 

## v1.1.0
### Added
- LEARCredentialEmployee issuance in a synchronous way.
- DOME Trust Framework integration to register issuers and participants.
### Changed
- Issuances API to support various issuance types.

