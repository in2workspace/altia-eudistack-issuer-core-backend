package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.GetAuthorizationServerMetadataWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationServerMetadata;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.Set;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(AuthorizationServerMetadataController.class)
class AuthorizationServerMetadataControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    ErrorResponseFactory errorResponseFactory;

    @MockBean
    private NonceService nonceService;

    @MockBean
    private GetAuthorizationServerMetadataWorkflow getAuthorizationServerMetadataWorkflow;

    @MockBean
    private IssuanceMetrics issuanceMetrics;

    @MockBean
    private TenantRegistryService tenantRegistryService;

    @MockBean
    private UrlResolver urlResolver;

    @MockBean
    private AccessTokenService accessTokenService;

    @Test
    void testGetAuthorizationServerMetadataSuccess() {
        // Arrange
        AuthorizationServerMetadata expectedAuthorizationServerMetadata = AuthorizationServerMetadata.builder()
                .issuer("https://issuer.example.com")
                .tokenEndpoint("https://issuer.example.com/oauth/token")
                .responseTypesSupported(Set.of("token"))
                .preAuthorizedGrantAnonymousAccessSupported(true)
                .build();
        // Mock
        when(urlResolver.publicIssuerBaseUrl(org.mockito.ArgumentMatchers.any()))
                .thenReturn("https://issuer.example.com");
        when(getAuthorizationServerMetadataWorkflow.execute(anyString(), anyString()))
                .thenReturn(Mono.just(expectedAuthorizationServerMetadata));
        // Act + Assert
        webTestClient
                .get()
                .uri("/.well-known/openid-configuration")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.CONTENT_LANGUAGE, "en")
                .expectBody(AuthorizationServerMetadata.class)
                .isEqualTo(expectedAuthorizationServerMetadata);
    }

    // EUD-215: signed metadata isn't implemented - an Accept: application/jwt
    // request must still get the plain JSON body back (200), not a 406.
    @Test
    void testGetAuthorizationServerMetadata_withUnsupportedAcceptHeader_stillReturns200() {
        // Arrange
        AuthorizationServerMetadata expectedAuthorizationServerMetadata = AuthorizationServerMetadata.builder()
                .issuer("https://issuer.example.com")
                .tokenEndpoint("https://issuer.example.com/oauth/token")
                .responseTypesSupported(Set.of("token"))
                .preAuthorizedGrantAnonymousAccessSupported(true)
                .build();
        // Mock
        when(urlResolver.publicIssuerBaseUrl(org.mockito.ArgumentMatchers.any()))
                .thenReturn("https://issuer.example.com");
        when(getAuthorizationServerMetadataWorkflow.execute(anyString(), anyString()))
                .thenReturn(Mono.just(expectedAuthorizationServerMetadata));
        // Act + Assert
        webTestClient
                .get()
                .uri("/.well-known/openid-configuration")
                .accept(MediaType.valueOf("application/jwt"))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(AuthorizationServerMetadata.class)
                .isEqualTo(expectedAuthorizationServerMetadata);
    }

    // EUD-215: OID4VCI 1.0 §12.2.2 - same well-known-before-path shape as
    // the credential issuer metadata endpoint.
    @Test
    void testGetAuthorizationServerMetadata_withIssuerPathSuffix_Success() {
        // Arrange
        AuthorizationServerMetadata expectedAuthorizationServerMetadata = AuthorizationServerMetadata.builder()
                .issuer("https://issuer.example.com/issuer")
                .tokenEndpoint("https://issuer.example.com/issuer/oauth/token")
                .responseTypesSupported(Set.of("token"))
                .preAuthorizedGrantAnonymousAccessSupported(true)
                .build();
        // Mock
        when(urlResolver.publicIssuerBaseUrl(org.mockito.ArgumentMatchers.any()))
                .thenReturn("https://issuer.example.com/issuer");
        when(getAuthorizationServerMetadataWorkflow.execute(anyString(), anyString()))
                .thenReturn(Mono.just(expectedAuthorizationServerMetadata));
        // Act + Assert
        webTestClient
                .get()
                .uri("/.well-known/oauth-authorization-server/issuer")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthorizationServerMetadata.class)
                .isEqualTo(expectedAuthorizationServerMetadata);
    }

}
