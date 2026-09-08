package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.model.ClientAttestationHeaders;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.REFRESH_TOKEN_GRANT_TYPE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(TokenController.class)
class TokenControllerTest {

    @MockBean
    TokenService tokenService;

    @Autowired
    WebTestClient webTestClient;

    @MockBean
    ErrorResponseFactory errorResponseFactory;

    @MockBean
    NonceService nonceService;

    @MockBean
    IssuanceMetrics issuanceMetrics;

    @MockBean
    IssuerProperties issuerProperties;

    @MockBean
    TenantRegistryService tenantRegistryService;

    @MockBean
    es.in2.issuer.backend.shared.domain.spi.UrlResolver urlResolver;

    @MockBean
    AccessTokenService accessTokenService;

    @Test
    void testHandleTokenRequest_RefreshTokenGrant_ShouldReturnOk() {
        String grantType = REFRESH_TOKEN_GRANT_TYPE;
        String refreshToken = "rt-123";
        TokenResponse tokenResponse = new TokenResponse(
                "access-token",
                "token-type",
                3600L,
                "1234");

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn("https://issuer.example.com");
        when(tokenService.exchangeToken(any(TokenRequest.class), isNull(), any(ClientAttestationHeaders.class),
                any(String.class), any(String.class)))
                .thenReturn(Mono.just(tokenResponse));

        webTestClient
                .mutateWith(csrf())
                .post()
                .uri("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters
                        .fromFormData("grant_type", grantType)
                        .with("refresh_token", refreshToken))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(TokenResponse.class)
                .isEqualTo(tokenResponse);
    }
}
