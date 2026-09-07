package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CorsIntegrationIT {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    void optionsRequest_FromAllowedOrigin_ReturnsCorsHeaders() {
      String allowedOrigin = "http://localhost:4200";

        webTestClient.options()
                .uri("/.well-known/openid-credential-issuer")
                .header("Origin", allowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", "Api-Version, Content-Type")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", "*")
                .expectHeader().valueEquals("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
                .expectHeader().valueMatches("Access-Control-Allow-Headers", ".*Api-Version.*");
    }

    @Test
    void optionsRequest_FromDisallowedOrigin_ReturnsOpenCorsHeaders() {
        String disallowedOrigin = "https://malicious.com";

        webTestClient.options()
                .uri("/.well-known/openid-credential-issuer")
                .header("Origin", disallowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", "*");
    }

    @Test
    void optionsRequest_FromLocalhost4200_ReturnsOpenCorsHeaders() {
        String allowedOrigin = "http://localhost:4200";

        webTestClient.options()
                .uri("/oid4vci/v1/authorize")
                .header("Origin", allowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", "*");
    }

    @Test
    void optionsRequest_RestrictedEndpoint_FromAllowedOrigin_ReturnsOrigin() {
        String allowedOrigin = "https://sandbox.127.0.0.1.nip.io:4443";

        webTestClient.options()
                .uri("/api/v1/issuances")
                .header("Origin", allowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", allowedOrigin);
    }

    @Test
    void optionsRequest_RestrictedEndpoint_FromDisallowedOrigin_IsForbidden() {
        String disallowedOrigin = "https://malicious.com";

        webTestClient.options()
                .uri("/api/v1/issuances")
                .header("Origin", disallowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .exchange()
                .expectStatus().isForbidden();
    }
}
