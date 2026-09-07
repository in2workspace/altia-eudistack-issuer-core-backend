package es.in2.issuer.backend.shared.infrastructure.config.security;

import es.in2.issuer.backend.shared.domain.service.AuditService;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityConfigTest {

    @Mock
    private CustomAuthenticationManager customAuthenticationManager;
    @Mock
    private ProblemAuthenticationEntryPoint entryPoint;
    @Mock
    private ProblemAccessDeniedHandler deniedHandler;
    @Mock
    private CorsFilterConfig corsConfig;
    @Mock
    private AuditService auditService;

    private WebFilterChainProxy securityProxy;

    @BeforeEach
    void setUp() {
        when(corsConfig.corsConfigurationSource()).thenReturn(new UrlBasedCorsConfigurationSource());

        SecurityConfig securityConfig = new SecurityConfig(
                customAuthenticationManager,
                corsConfig,
                auditService
        );

        SecurityWebFilterChain chain = securityConfig.unifiedFilterChain(
                ServerHttpSecurity.http(),
                entryPoint,
                deniedHandler
        );

        securityProxy = new WebFilterChainProxy(chain);
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private void stubEntryPointTo401() {
        doAnswer(inv -> {
            var exchange = inv.getArgument(0, org.springframework.web.server.ServerWebExchange.class);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }).when(entryPoint).commence(any(), any());
    }

    private void stubAuthManagerSuccess() {
        Jwt jwt = buildJwt(Map.of("scope", "any"), "subject-123");
        Authentication auth = new JwtAuthenticationToken(jwt, Collections.emptyList(), "subject-123");
        when(customAuthenticationManager.authenticate(any())).thenReturn(Mono.just(auth));
    }

    private HttpStatusCode executeFilter(MockServerWebExchange exchange) {
        securityProxy.filter(exchange, ex -> {
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return ex.getResponse().setComplete();
        }).block();
        return exchange.getResponse().getStatusCode();
    }

    private Jwt buildJwt(Map<String, Object> claims, String subject) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .headers(h -> h.put("alg", "none"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .claims(c -> c.putAll(claims));

        if (subject != null) {
            builder.subject(subject);
        }
        return builder.build();
    }

    // ── Public GET endpoints (permitAll) ────────────────────────────────

    @Nested
    @DisplayName("Public GET endpoints — should be accessible without authentication")
    class PublicGetEndpoints {

        @Test
        void credentialIssuerMetadata_get_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH).build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }

        @Test
        void authorizationServerMetadata_get_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH).build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }

        // EUD-215: OID4VCI 1.0 §12.2.2 - well-known inserted before the
        // issuer's own path (e.g. /.well-known/openid-credential-issuer/issuer)
        // must be public too, not just the bare form.
        @Test
        void credentialIssuerMetadata_get_withIssuerPathSuffix_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH + "/issuer").build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }

        @Test
        void authorizationServerMetadata_get_withIssuerPathSuffix_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH + "/issuer").build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }

        @Test
        void oauthAuthorizationServerMetadata_get_withIssuerPathSuffix_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH + "/issuer").build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }

        @Test
        void credentialOffer_get_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(OID4VCI_BASE_PATH + "/credential-offer/abc123").build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }

        @Test
        void health_get_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(HEALTH_PATH).build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }

        @Test
        void statusList_get_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(STATUS_LIST_BASE).build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }

        @Test
        void issuanceCredentialsStatus_get_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(ISSUANCE_BASE_PATH + "/credentials/status/list").build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }

        @Test
        void prometheus_get_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(PROMETHEUS_PATH).build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }
    }

    // ── Public POST endpoints (permitAll) ────────────────────────────────

    @Nested
    @DisplayName("Public POST endpoints — should be accessible without authentication")
    class PublicPostEndpoints {

        @Test
        void oauthToken_post_shouldReturn200_withoutAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(OAUTH_TOKEN_PATH).build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
        }
    }

    // ── Authenticated endpoints — 401 without auth ──────────────────────

    @Nested
    @DisplayName("Authenticated endpoints — should return 401 without credentials")
    class AuthenticatedEndpointsNoAuth {

        @BeforeEach
        void stubEntryPoint() {
            stubEntryPointTo401();
        }

        @Test
        void statusList_post_shouldReturn401_whenNoAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(STATUS_LIST_BASE).build()
            );
            assertEquals(HttpStatus.UNAUTHORIZED, executeFilter(exchange));
        }

        @Test
        void oid4vciCredential_post_shouldReturn401_whenNoAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(OID4VCI_CREDENTIAL_PATH).build()
            );
            assertEquals(HttpStatus.UNAUTHORIZED, executeFilter(exchange));
        }

        @Test
        void oid4vciNotification_post_shouldReturn401_whenNoAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(OID4VCI_NOTIFICATION_PATH).build()
            );
            assertEquals(HttpStatus.UNAUTHORIZED, executeFilter(exchange));
        }

        @Test
        void issuances_post_shouldReturn401_whenNoAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(ISSUANCES_PATH).build()
            );
            assertEquals(HttpStatus.UNAUTHORIZED, executeFilter(exchange));
        }

        @Test
        void intake_post_shouldReturn401_whenNoAuth() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(INTAKE_BASE_PATH).build()
            );
            assertEquals(HttpStatus.UNAUTHORIZED, executeFilter(exchange));
        }

    }

    // ── Authenticated endpoints — 200 with valid Bearer token ───────────

    @Nested
    @DisplayName("Authenticated endpoints — should return 200 with valid Bearer token")
    class AuthenticatedEndpointsWithAuth {

        @BeforeEach
        void stubAuth() {
            stubAuthManagerSuccess();
        }

        @Test
        void statusList_post_shouldReturn200_whenAuthenticated() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(STATUS_LIST_BASE)
                            .header(HttpHeaders.AUTHORIZATION, "Bearer good-token")
                            .build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
            verify(customAuthenticationManager).authenticate(any());
        }

        @Test
        void oid4vciCredential_post_shouldReturn200_whenAuthenticated() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(OID4VCI_CREDENTIAL_PATH)
                            .header(HttpHeaders.AUTHORIZATION, "Bearer good-token")
                            .build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
            verify(customAuthenticationManager).authenticate(any());
        }

        @Test
        void oid4vciNotification_post_shouldReturn200_whenAuthenticated() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(OID4VCI_NOTIFICATION_PATH)
                            .header(HttpHeaders.AUTHORIZATION, "Bearer good-token")
                            .build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
            verify(customAuthenticationManager).authenticate(any());
        }

        @Test
        void issuances_post_shouldReturn200_whenAuthenticated() {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.post(ISSUANCES_PATH)
                            .header(HttpHeaders.AUTHORIZATION, "Bearer good-token")
                            .build()
            );
            assertEquals(HttpStatus.OK, executeFilter(exchange));
            verify(customAuthenticationManager).authenticate(any());
        }

    }

    // ── Intake gate (EUD-75, US-02) — M2M authorization on top of auth ──

    @Nested
    @DisplayName("Intake gate — authorizes M2M callers, denies the rest with 403")
    class IntakeAuthorizationGate {

        private void stubAuthManagerM2m(boolean canTriggerIssuance) {
            Jwt jwt = buildJwt(Map.of(
                    "caller_type", "M2M",
                    "client_id", "acme-hr",
                    "can_trigger_issuance", canTriggerIssuance
            ), "acme-hr");
            Authentication auth = new JwtAuthenticationToken(jwt, Collections.emptyList(), "acme-hr");
            when(customAuthenticationManager.authenticate(any())).thenReturn(Mono.just(auth));
        }

        private void stubAccessDeniedHandlerTo403() {
            doAnswer(inv -> {
                var exchange = inv.getArgument(0, org.springframework.web.server.ServerWebExchange.class);
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }).when(deniedHandler).handle(any(), any());
        }

        private MockServerWebExchange intakeRequest() {
            return MockServerWebExchange.from(
                    MockServerHttpRequest.post(INTAKE_BASE_PATH)
                            .header(HttpHeaders.AUTHORIZATION, "Bearer good-token")
                            .build()
            );
        }

        @Test
        void intake_post_shouldReturn200_whenM2mAuthorized() {
            stubAuthManagerM2m(true);

            assertEquals(HttpStatus.OK, executeFilter(intakeRequest()));
            verify(auditService).auditSuccess(eq("intake.auth.success"), eq("acme-hr"), any(), any(), any());
        }

        @Test
        void intake_post_shouldReturn403_whenPrincipalIsNotM2m() {
            // EC-04: token valid for this issuer but not caller_type=M2M (e.g. a human LEAR token)
            Jwt jwt = buildJwt(Map.of("scope", "any"), "human-subject");
            Authentication auth = new JwtAuthenticationToken(jwt, Collections.emptyList(), "human-subject");
            when(customAuthenticationManager.authenticate(any())).thenReturn(Mono.just(auth));
            stubAccessDeniedHandlerTo403();

            assertEquals(HttpStatus.FORBIDDEN, executeFilter(intakeRequest()));
            verify(auditService).auditFailure(eq("intake.auth.failure"), any(), eq("not_m2m"), any());
        }

        @Test
        void intake_post_shouldReturn403_whenInsufficientScope() {
            // EC-03: M2M caller, but can_trigger_issuance=false
            stubAuthManagerM2m(false);
            stubAccessDeniedHandlerTo403();

            assertEquals(HttpStatus.FORBIDDEN, executeFilter(intakeRequest()));
            verify(auditService).auditFailure(eq("intake.auth.failure"), eq("acme-hr"), eq("insufficient_scope"), any());
        }
    }
}
