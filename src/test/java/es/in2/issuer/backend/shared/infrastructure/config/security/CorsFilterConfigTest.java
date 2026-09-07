package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CorsFilterConfigTest {

    private CorsOriginsLoader corsOriginsLoader;
    private CorsFilterConfig corsConfig;
    private static final List<String> ALLOWED_ORIGINS = List.of(
            "https://wallet.example.com",
            "https://another.com",
            "https://*.stg.eudistack.net");

    @BeforeEach
    void setUp() {
        corsOriginsLoader = mock(CorsOriginsLoader.class);
        corsConfig = new CorsFilterConfig(corsOriginsLoader);
        when(corsOriginsLoader.loadOrigins()).thenReturn(ALLOWED_ORIGINS);
    }

    @Test
    void corsWebFilter_IsRegisteredAsStandaloneBean() {
        CorsWebFilter filter = corsConfig.corsWebFilter();
        assertThat(filter).isNotNull();
    }

    @ParameterizedTest
    @MethodSource("provideCorsTestCases")
    void corsConfigurationSource_ValidatesPathCORS(String path, HttpMethod method, boolean isOpen) {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.method(method, path).build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).as("Path: " + path).isNotNull();
        if (isOpen) {
            assertThat(config.getAllowedOrigins()).containsExactly("*");
        } else {
            assertThat(config.getAllowedOriginPatterns()).containsExactlyElementsOf(ALLOWED_ORIGINS);
        }
        assertThat(config.getAllowCredentials()).isNotEqualTo(Boolean.TRUE);
    }

    private static java.util.stream.Stream<Arguments> provideCorsTestCases() {
        return java.util.stream.Stream.of(
                // Open Endpoints
                Arguments.of("/.well-known/openid-credential-issuer", HttpMethod.GET, true),
                Arguments.of("/oid4vci/v1/authorize", HttpMethod.GET, true),
                Arguments.of("/api/v1/bootstrap", HttpMethod.GET, true),
                Arguments.of("/w3c/v1/credentials/status/123", HttpMethod.GET, true),
                Arguments.of("/token/v1/credentials/status/456", HttpMethod.GET, true),
                Arguments.of("/issuance/v1/credentials/status/789", HttpMethod.GET, true),
                Arguments.of("/oauth/token", HttpMethod.POST, true),
                Arguments.of("/health", HttpMethod.GET, true),
                Arguments.of("/prometheus", HttpMethod.GET, true),
                Arguments.of("/springdoc/swagger-ui.html", HttpMethod.GET, true),
                Arguments.of("/credential-offer/refresh/123", HttpMethod.GET, true),
                // Restricted Endpoints
                Arguments.of("/api/v1/issuances", HttpMethod.GET, false),
                Arguments.of("/admin/v1/credential-catalog", HttpMethod.GET, false)
        );
    }

    @Test
    void CorsConfigurationSource_ApiPath_AllowsStandardHttpMethods() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/issuances").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedMethods())
                .containsAll(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    }

    @Test
    void CorsConfigurationSource_ApiPath_AllowsRequiredHeaders() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/v1/issuances").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedHeaders())
                .contains("Content-Type", "Authorization", "DPoP",
                        "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP",
                        "Api-Version", "X-ID-Token", "X-Idempotency-Key", "X-Tenant",
                        "X-Bootstrap-Token");
    }

    @Test
    void CorsConfigurationSource_RestrictedApiPath_ExposesLocationHeader() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/issuances").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getExposedHeaders()).contains("Location");
    }

    @Test
    void CorsConfigurationSource_BootstrapPath_AllowsRequiredHeaders() {
        UrlBasedCorsConfigurationSource source = corsConfig.corsConfigurationSource();
        var exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/bootstrap").build()
        );

        CorsConfiguration config = source.getCorsConfiguration(exchange);

        assertThat(config).isNotNull();
        assertThat(config.getAllowedHeaders()).contains("X-Bootstrap-Token", "Api-Version");
        assertThat(config.getExposedHeaders()).contains("Location");
    }
}