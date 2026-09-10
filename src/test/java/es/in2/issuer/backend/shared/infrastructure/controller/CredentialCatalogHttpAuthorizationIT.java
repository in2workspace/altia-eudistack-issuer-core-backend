package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_CATALOG_PATH;

/**
 * Closes TD-3 / TDG-24: the missing HTTP -&gt; authentication -&gt; authorization -&gt; DB
 * integration coverage for the catalog's lowest-privilege role (the tenant's operator,
 * {@code LEAR}, opened by AD-16). Every other test in the Story either bypasses HTTP
 * entirely ({@code CredentialCatalogTransactionalIT} invokes the domain service
 * directly) or mocks {@code AuthorizationContext} ({@code CredentialCatalogControllerTest}).
 *
 * <p>Here the bearer token is a real, ES256-signed JWT minted via
 * {@link PostgresIntegrationBase#mintOperatorAccessToken} -- the same signing key
 * {@code CustomAuthenticationManager} verifies against, so this exercises the actual
 * authentication filter and {@code AccessTokenServiceImpl.resolveRole}, not a
 * hand-crafted token injected past them.
 *
 * <p>Uses the pre-registered {@code e2e-tenant-a}/{@code e2e-tenant-b} schemas (not a
 * private throwaway schema): {@code TenantDomainWebFilter} rejects any tenant absent from
 * {@code tenant_registry} with a 404 before the request ever reaches this controller, so
 * -- unlike {@code TenantDeliveryModesMigrationIT}, which drives Flyway directly below the
 * HTTP layer -- an unregistered schema does not work here. Shares these two schemas with
 * {@code CredentialCatalogTransactionalIT}, which only ever calls the domain service
 * directly and never touches {@code tenant_config}/{@code admin_organization_id}, so this
 * class's own seeding cannot affect its assertions; both classes reset the catalog's
 * enabled set explicitly before each test, so execution order does not matter either.
 */
class CredentialCatalogHttpAuthorizationIT extends PostgresIntegrationBase {

    private static final String TENANT_A = "e2e-tenant-a";
    private static final String TENANT_B = "e2e-tenant-b";
    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String ADMIN_ORG_ID = "admin-org-for-authz-it";
    private static final String OPERATOR_ORG_ID = "operator-org-for-authz-it";

    @BeforeEach
    void seedTenants() {
        seedAdminOrganizationId(TENANT_A);
        seedAdminOrganizationId(TENANT_B);
        seedEnabledProfile(TENANT_A);
    }

    @Test
    void operator_readsOwnTenantCatalog_returns200() {
        String token = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        webTestClient()
                .get().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_A)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void operator_attemptsWrite_returns403WithoutReachingTheService() {
        String token = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        webTestClient()
                .put().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_A)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"" + CONFIG_ID + "\"]}")
                .exchange()
                .expectStatus().isForbidden();
    }

    /** NFR-S-169-04 (inter-tenant isolation, extended to the lowest-privilege role): a
     *  token genuinely minted for tenant A must not read tenant B's catalog just because
     *  the caller sends {@code X-Tenant: B} -- {@code requireTenantMatch()}'s S1 fix. */
    @Test
    void tokenMintedForTenantA_usedAgainstTenantB_returns403TenantMismatch() {
        String token = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        webTestClient()
                .get().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_B)
                .exchange()
                .expectStatus().isForbidden();
    }

    // ---- helpers ---------------------------------------------------------------

    private void seedAdminOrganizationId(String tenant) {
        String schema = tenant + SCHEMA_SUFFIX;
        databaseClient.sql("INSERT INTO \"" + schema + "\".tenant_config (config_key, config_value) "
                        + "VALUES ('admin_organization_id', :value) "
                        + "ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value")
                .bind("value", ADMIN_ORG_ID)
                .then().block();
    }

    private void seedEnabledProfile(String tenant) {
        String schema = tenant + SCHEMA_SUFFIX;
        databaseClient.sql("INSERT INTO \"" + schema + "\".tenant_credential_profile "
                        + "(credential_configuration_id, enabled) VALUES (:configId, true) "
                        + "ON CONFLICT (credential_configuration_id) DO UPDATE SET enabled = true")
                .bind("configId", CONFIG_ID)
                .then().block();
    }
}
