package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
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
        when(tenantCredentialProfileService.updateCatalog(any()))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .put()
                .uri(CREDENTIAL_CATALOG_PATH)
                .header("Authorization", "Bearer token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"learcredential.employee.w3c.4\"]}")
                .exchange()
                .expectStatus().isOk();
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

        verify(tenantCredentialProfileService, never()).updateCatalog(any());
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

        verify(tenantCredentialProfileService, never()).updateCatalog(any());
    }

    @Test
    void updateCatalog_unknownId_returns400() {
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(admin()));
        when(tenantCredentialProfileService.updateCatalog(any()))
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

        verify(tenantCredentialProfileService, never()).updateCatalog(any());
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

        verify(tenantCredentialProfileService, never()).updateCatalog(any());
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
