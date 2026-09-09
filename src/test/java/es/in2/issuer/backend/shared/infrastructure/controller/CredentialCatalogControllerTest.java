package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.CredentialConfigurationNotEnabledException;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_CATALOG_PATH;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockitoBean(types = ReactiveAuthenticationManager.class)
@Import(ErrorResponseFactory.class)
@WebFluxTest(CredentialCatalogController.class)
class CredentialCatalogControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private AccessTokenService accessTokenService;

    @MockitoBean
    private TenantCredentialProfileService tenantCredentialProfileService;

    @MockitoBean
    private AuditService auditService;

    // Required only because @WebFluxTest loads all @ControllerAdvice and WebFilter beans:
    // Oidc4vciExceptionHandler depends on NonceService, IdempotencyFilter on IssuanceMetrics.
    @MockitoBean
    private NonceService nonceService;

    @MockitoBean
    private IssuanceMetrics issuanceMetrics;

    @MockitoBean
    private TenantRegistryService tenantRegistryService;

    @Test
    void getCatalog_asTenantAdmin_returns200WithEntries() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.just(List.of(
                        new CredentialCatalogEntryDto("learcredential.employee.w3c.4", "Employee", true, List.of(), List.of()))));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].credentialConfigurationId").isEqualTo("learcredential.employee.w3c.4")
                .jsonPath("$[0].enabled").isEqualTo(true);
    }

    @Test
    void getCatalog_asLear_returns403AndDoesNotReadCatalog() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(lear()));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isForbidden();

        verify(tenantCredentialProfileService, never()).getCatalog();
    }

    /**
     * A SysAdmin on the platform tenant holds a cross-tenant read-only view, so reads must
     * succeed; only writes are denied (see updateCatalog_asReadOnlyAdmin_returns403).
     */
    @Test
    void getCatalog_asReadOnlyAdmin_returns200() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(readOnlyAdmin()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.just(List.of(
                        new CredentialCatalogEntryDto("learcredential.employee.w3c.4", "Employee", true, List.of(), List.of()))));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].credentialConfigurationId").isEqualTo("learcredential.employee.w3c.4");
    }

    @Test
    void updateCatalog_asTenantAdmin_returns200() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}")
                .exchange()
                .expectStatus().isOk();

        // Security review (EUD-169, F2): a catalog write is a policy change and must be
        // audit-logged with the caller's organization as actor -- not just a plain log line.
        verify(auditService).auditSuccess(eq("tenant.credential_catalog.changed"), eq("org-1"), eq("credential-catalog"), anyString(), any());
    }

    @Test
    void updateCatalog_serviceFails_auditsFailureNotSuccess() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.error(new UnknownCredentialConfigurationException("Unknown credential configuration id(s): [nope]")));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"nope\"]}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(auditService).auditFailure(eq("tenant.credential_catalog.changed"), eq("org-1"), anyString(), any());
        verify(auditService, never()).auditSuccess(anyString(), anyString(), anyString(), anyString(), any());
    }

    @Test
    void updateCatalog_asLear_returns403AndDoesNotWrite() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(lear()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}")
                .exchange()
                .expectStatus().isForbidden();

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    @Test
    void updateCatalog_asReadOnlyAdmin_returns403() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(readOnlyAdmin()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}")
                .exchange()
                .expectStatus().isForbidden();

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    @Test
    void updateCatalog_unknownId_returns400() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.error(new UnknownCredentialConfigurationException(
                        "Unknown credential configuration id(s): [nope]")));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"nope\"]}")
                .exchange()
                .expectStatus().isBadRequest();
    }

    /**
     * AC-01: the catalog read carries both the eligible modes and the schema ceiling,
     * so the admin UI can disable the direct mode by reading the ceiling alone.
     */
    @Test
    void getCatalog_asTenantAdmin_includesDeliveryModesAndSchemaCeiling() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.just(List.of(
                        new CredentialCatalogEntryDto("learcredential.employee.w3c.4", "Employee", true,
                                List.of("email", "ui"), List.of("email", "ui")))));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].deliveryModes[0]").isEqualTo("email")
                .jsonPath("$[0].deliveryModes[1]").isEqualTo("ui")
                .jsonPath("$[0].schemaEligibleModes[0]").isEqualTo("email")
                .jsonPath("$[0].schemaEligibleModes[1]").isEqualTo("ui");
    }

    /**
     * AC-04: rejecting a mode above the schema ceiling is a 409 conflict, not a 400 --
     * distinct from the payload-shape errors below (ES-01..03).
     */
    @Test
    void updateCatalog_directAboveSchemaCeiling_returns409() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.error(new DeliveryModeNotEligibleException(
                        "Delivery mode 'direct' is not eligible for credential type "
                                + "'learcredential.employee.w3c.4': its schema requires cryptographic holder binding. "
                                + "Eligible modes: email,ui")));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                        + "\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":[\"direct\"]}}")
                .exchange()
                .expectStatus().isEqualTo(409);
    }

    /**
     * ES-01: an unknown delivery-mode token is a 400, parsed and rejected by the controller
     * itself -- the service is never reached.
     */
    @Test
    void updateCatalog_unknownDeliveryModeToken_returns400WithoutCallingService() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                        + "\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":[\"carrier-pigeon\"]}}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    /**
     * ES-02: an explicitly empty set of modes for a declared type is a 400, parsed and
     * rejected by the controller itself.
     */
    @Test
    void updateCatalog_emptyModesForDeclaredType_returns400WithoutCallingService() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                        + "\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":[]}}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    /**
     * F3 (security review): a JSON `null` value for a declared type must not reach
     * String.join as an NPE -- caught by UpdateCredentialCatalogRequest's own bean
     * validation (F4) before this even reaches the controller body.
     */
    @Test
    void updateCatalog_nullModesForDeclaredType_returns400WithoutCallingService() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                        + "\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":null}}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    /**
     * ES-03: modes declared for a type outside enabledConfigurationIds (or the global
     * registry) are a 400, surfaced by the service -- unlike ES-01/02 this one needs the
     * enabled-ids ⊆ registry / map ⊆ enabled-ids checks the service itself owns.
     */
    @Test
    void updateCatalog_modesForNotEnabledType_returns400() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any(), any()))
                .thenReturn(Mono.error(new InvalidDeliveryConfigException(
                        "Delivery modes declared for credential configuration id(s) not enabled in this request: [other.type]")));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"],"
                        + "\"deliveryModesByConfigurationId\":{\"other.type\":[\"email\"]}}")
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void getCatalog_tenantWithNothingEnabled_returns404() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.getCatalog())
                .thenReturn(Mono.error(new CredentialCatalogNotConfiguredException(
                        "No credential configuration enabled for tenant 'demo'")));

        webTestClient.get()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void updateCatalog_emptySet_returns400AndDoesNotWrite() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[]}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    @Test
    void updateCatalog_missingRequiredField_returns400() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(tenantCredentialProfileService, never()).updateCatalog(any(), any());
    }

    // ---- PATCH /admin/v1/credential-catalog (AC-11) ----------------------------

    @Test
    void patchDeliveryModes_asTenantAdmin_returns200() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateDeliveryModes(any()))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":[\"email\"]}}")
                .exchange()
                .expectStatus().isOk();

        // AD-15: shares the PUT's audit event, discriminated by "action" in the detail map.
        verify(auditService).auditSuccess(eq("tenant.credential_catalog.changed"), eq("org-1"), eq("credential-catalog"), anyString(), any());
    }

    /**
     * ES-10: a declared credential_configuration_id that is not currently enabled for
     * the tenant is a 409, not a 400 -- distinct from the schema-ceiling 409 below (AD-13).
     */
    @Test
    void patchDeliveryModes_ccidNotEnabled_returns409() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateDeliveryModes(any()))
                .thenReturn(Mono.error(new CredentialConfigurationNotEnabledException(
                        "Credential configuration id 'learcredential.employee.w3c.4' is not enabled for this tenant")));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":[\"email\"]}}")
                .exchange()
                .expectStatus().isEqualTo(409)
                .expectBody()
                .jsonPath("$.type").isEqualTo("credential_configuration_not_enabled");
    }

    /**
     * AC-04, via the point-adjustment path: a mode outside the schema ceiling is 409
     * with the same code the PUT uses.
     */
    @Test
    void patchDeliveryModes_directAboveSchemaCeiling_returns409() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateDeliveryModes(any()))
                .thenReturn(Mono.error(new DeliveryModeNotEligibleException(
                        "Delivery mode 'direct' is not eligible for credential type "
                                + "'learcredential.employee.w3c.4': its schema requires cryptographic holder binding. "
                                + "Eligible modes: email,ui")));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":[\"direct\"]}}")
                .exchange()
                .expectStatus().isEqualTo(409)
                .expectBody()
                .jsonPath("$.type").isEqualTo("delivery_mode_not_eligible");
    }

    @Test
    void patchDeliveryModes_emptyMap_returns400WithoutCallingService() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"deliveryModesByConfigurationId\":{}}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(tenantCredentialProfileService, never()).updateDeliveryModes(any());
    }

    @Test
    void patchDeliveryModes_unknownDeliveryModeToken_returns400WithoutCallingService() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":[\"carrier-pigeon\"]}}")
                .exchange()
                .expectStatus().isBadRequest();

        verify(tenantCredentialProfileService, never()).updateDeliveryModes(any());
    }

    @Test
    void patchDeliveryModes_asLear_returns403AndDoesNotWrite() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(lear()));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":[\"email\"]}}")
                .exchange()
                .expectStatus().isForbidden();

        verify(tenantCredentialProfileService, never()).updateDeliveryModes(any());
    }

    @Test
    void patchDeliveryModes_asReadOnlyAdmin_returns403() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(readOnlyAdmin()));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"deliveryModesByConfigurationId\":{\"learcredential.employee.w3c.4\":[\"email\"]}}")
                .exchange()
                .expectStatus().isForbidden();

        verify(tenantCredentialProfileService, never()).updateDeliveryModes(any());
    }

    private static AuthorizationContext admin() {
        return new AuthorizationContext("org-1", UserRole.TENANT_ADMIN, false, "tenant");
    }

    private static AuthorizationContext readOnlyAdmin() {
        return new AuthorizationContext("org-1", UserRole.SYSADMIN, true, "platform");
    }

    private static AuthorizationContext lear() {
        return new AuthorizationContext("org-1", UserRole.LEAR, false, "tenant");
    }
}
