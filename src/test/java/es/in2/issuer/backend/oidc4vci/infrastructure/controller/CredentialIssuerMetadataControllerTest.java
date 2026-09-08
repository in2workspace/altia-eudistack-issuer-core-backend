package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.GetCredentialIssuerMetadataWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Set;

import static org.mockito.Mockito.*;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(CredentialIssuerMetadataController.class)
class CredentialIssuerMetadataControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    ErrorResponseFactory errorResponseFactory;

    @MockBean
    private NonceService nonceService;

    @MockBean
    private GetCredentialIssuerMetadataWorkflow getCredentialIssuerMetadataWorkflow;

    @MockBean
    private IssuanceMetrics issuanceMetrics;

    @MockBean
    private TenantRegistryService tenantRegistryService;

    @MockBean
    private es.in2.issuer.backend.shared.domain.spi.UrlResolver urlResolver;

    @MockBean
    private AccessTokenService accessTokenService;

    @Test
    void testGetCredentialIssuer_Metadata_Success() {
        // Arrange
        CredentialIssuerMetadata expectedCredentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("https://issuer.example.com")
                .credentialEndpoint("https://issuer.example.com/oid4vci/v1/credential")
                .credentialConfigurationsSupported(Map.of(
                        "learcredential.employee.w3c.4", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format("jwt_vc_json")
                                .scope("lear_credential_employee")
                                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                                .proofTypesSupported(Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                                        .proofSigningAlgValuesSupported(Set.of("ES256"))
                                        .build()))
                                .credentialMetadata(null)
                                .vct(null)
                                .build(),
                        "learcredential.machine.w3c.3", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format("jwt_vc_json")
                                .scope("lear_credential_machine")
                                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                                .credentialMetadata(null)
                                .vct(null)
                                .build(),
                        "VerifiableCertification", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format("jwt_vc_json")
                                .scope("verifiable_certification")
                                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                                .credentialMetadata(null)
                                .vct(null)
                                .build()
                ))
                .build();
        //Mock
        when(urlResolver.publicIssuerBaseUrl(org.mockito.ArgumentMatchers.any()))
                .thenReturn("https://issuer.example.com");
        when(getCredentialIssuerMetadataWorkflow.execute(anyString(), anyString()))
                .thenReturn(Mono.just(expectedCredentialIssuerMetadata));
        ServerWebExchange mockExchange = mock(ServerWebExchange.class);
        ServerHttpResponse mockResponse = mock(ServerHttpResponse.class);
        when(mockExchange.getResponse()).thenReturn(mockResponse);
        HttpHeaders mockHeaders = new HttpHeaders();
        when(mockResponse.getHeaders()).thenReturn(mockHeaders);
        // Act
        webTestClient
                .get()
                .uri("/.well-known/openid-credential-issuer")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.CONTENT_LANGUAGE, "en")
                .expectBody(CredentialIssuerMetadata.class)
                .isEqualTo(expectedCredentialIssuerMetadata);
    }

    // EUD-215: signed metadata (OID4VCI 1.0 §12.2.3) isn't implemented, but an
    // Accept: application/jwt request must still get the plain JSON body back
    // (200), not a 406 - the conformance suite's "-signed" test module treats
    // a hard rejection as a failure, not as "not signed, skip".
    @Test
    void testGetCredentialIssuerMetadata_withUnsupportedAcceptHeader_stillReturns200() {
        // Arrange
        CredentialIssuerMetadata expectedCredentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("https://issuer.example.com")
                .credentialEndpoint("https://issuer.example.com/oid4vci/v1/credential")
                .credentialConfigurationsSupported(Map.of())
                .build();
        // Mock
        when(urlResolver.publicIssuerBaseUrl(org.mockito.ArgumentMatchers.any()))
                .thenReturn("https://issuer.example.com");
        when(getCredentialIssuerMetadataWorkflow.execute(anyString(), anyString()))
                .thenReturn(Mono.just(expectedCredentialIssuerMetadata));
        ServerWebExchange mockExchange = mock(ServerWebExchange.class);
        ServerHttpResponse mockResponse = mock(ServerHttpResponse.class);
        when(mockExchange.getResponse()).thenReturn(mockResponse);
        HttpHeaders mockHeaders = new HttpHeaders();
        when(mockResponse.getHeaders()).thenReturn(mockHeaders);
        // Act
        webTestClient
                .get()
                .uri("/.well-known/openid-credential-issuer")
                .accept(MediaType.valueOf("application/jwt"))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(CredentialIssuerMetadata.class)
                .isEqualTo(expectedCredentialIssuerMetadata);
    }

    // EUD-215: OID4VCI 1.0 §12.2.2 - a compliant client derives the metadata
    // URL by inserting the well-known path before the issuer's own path
    // (e.g. /.well-known/openid-credential-issuer/issuer, not the other way
    // around). The controller must accept that shape too.
    @Test
    void testGetCredentialIssuerMetadata_withIssuerPathSuffix_Success() {
        // Arrange
        CredentialIssuerMetadata expectedCredentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("https://issuer.example.com/issuer")
                .credentialEndpoint("https://issuer.example.com/issuer/oid4vci/v1/credential")
                .credentialConfigurationsSupported(Map.of())
                .build();
        // Mock
        when(urlResolver.publicIssuerBaseUrl(org.mockito.ArgumentMatchers.any()))
                .thenReturn("https://issuer.example.com/issuer");
        when(getCredentialIssuerMetadataWorkflow.execute(anyString(), anyString()))
                .thenReturn(Mono.just(expectedCredentialIssuerMetadata));
        ServerWebExchange mockExchange = mock(ServerWebExchange.class);
        ServerHttpResponse mockResponse = mock(ServerHttpResponse.class);
        when(mockExchange.getResponse()).thenReturn(mockResponse);
        HttpHeaders mockHeaders = new HttpHeaders();
        when(mockResponse.getHeaders()).thenReturn(mockHeaders);
        // Act
        webTestClient
                .get()
                .uri("/.well-known/openid-credential-issuer/issuer")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .exchange()
                .expectStatus().isOk()
                .expectBody(CredentialIssuerMetadata.class)
                .isEqualTo(expectedCredentialIssuerMetadata);
    }

}
