package es.in2.issuer.backend.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import org.testcontainers.containers.PostgreSQLContainer;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;

/**
 * Shared Testcontainers Postgres fixture for EUD-75 (US-02) integration
 * tests. The container and its {@code public.tenant_registry} seed (see
 * {@code db/it/tenant-registry-init.sql}) are declared as static fields on
 * this base class, so every subclass reuses the same running container and
 * (when Spring Test's context cache hits) the same {@code ApplicationContext}
 * — the standard Testcontainers "singleton container" pattern.
 *
 * <p>{@code tenant_registry} must be populated before the Spring context
 * starts because {@code TenantSchemaFlywayMigrator} reads it from an
 * {@code ApplicationRunner} to decide which {@code <tenant>_issuer} schemas
 * to create and Flyway-migrate; {@code withInitScript} runs via JDBC right
 * after the container starts, ahead of context refresh.
 *
 * <p>Started eagerly in a static initializer (the classic Testcontainers
 * "singleton container" pattern) rather than via {@code @Testcontainers}/
 * {@code @Container} — that JUnit extension's {@code beforeAll} does not
 * reliably finish before Spring's {@code @DynamicPropertySource} suppliers
 * get evaluated during context bootstrap, which raced and failed with
 * "Mapped port can only be obtained after the container is started".
 * Class-init order has no such ambiguity: it always runs first.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class PostgresIntegrationBase {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withInitScript("db/it/tenant-registry-init.sql");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void registerPostgresProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () -> "r2dbc:postgresql://" + POSTGRES.getHost()
                + ":" + POSTGRES.getFirstMappedPort() + "/" + POSTGRES.getDatabaseName());
        registry.add("spring.r2dbc.username", POSTGRES::getUsername);
        registry.add("spring.r2dbc.password", POSTGRES::getPassword);
        registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
    }

    @LocalServerPort
    protected int port;

    @Autowired
    protected DatabaseClient databaseClient;

    @Autowired
    protected PasswordEncoder apiClientPasswordEncoder;

    @Autowired
    protected JWTService jwtService;

    @Autowired
    protected ObjectMapper objectMapper;

    protected WebTestClient webTestClient() {
        return WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port + "/issuer")
                .responseTimeout(Duration.ofSeconds(10))
                .build();
    }

    /** Inserts a row directly into {@code <tenant>_issuer.api_client}, schema-qualified so it works
     *  regardless of the caller's R2DBC search_path. */
    protected Mono<Void> seedApiClient(String tenant, String clientId, String rawSecret,
                                        boolean canTriggerIssuance, String authorizationStatus) {
        String secretHash = apiClientPasswordEncoder.encode(rawSecret);
        String schema = tenant + SCHEMA_SUFFIX;
        return databaseClient.sql("INSERT INTO \"" + schema + "\".api_client "
                        + "(client_id, authorization_status, can_trigger_issuance, secret_hash) "
                        + "VALUES (:clientId, :status, :canTriggerIssuance, :secretHash)")
                .bind("clientId", clientId)
                .bind("status", authorizationStatus)
                .bind("canTriggerIssuance", canTriggerIssuance)
                .bind("secretHash", secretHash)
                .then();
    }

    protected WebTestClient.ResponseSpec requestToken(String tenant, String clientId, String clientSecret) {
        return webTestClient()
                .post().uri("/oauth/token")
                .header(X_TENANT_HEADER, tenant)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", "client_credentials")
                        .with("client_id", clientId)
                        .with("client_secret", clientSecret))
                .exchange();
    }

    /**
     * Mints a real, ES256-signed user access token (TD-3 / TDG-24): signed through
     * {@link JWTService#issueJWT} using the exact same {@code CryptoComponent.getECKey()}
     * bean {@code CustomAuthenticationManager} verifies against, with {@code iss} set to
     * this test server's own public issuer base URL -- a token minted this way is
     * genuinely accepted by the running application's real authentication filter, not a
     * hand-crafted unsigned token injected past it. Lets an IT drive the actual
     * HTTP -> authentication -> authorization -> DB path for a real user role
     * (TENANT_ADMIN / LEAR), which no fixture in this base class could do before --
     * {@link #requestToken} only covers the M2M {@code client_credentials} grant.
     *
     * <p>Role resolution ({@code AccessTokenServiceImpl.resolveRole}) is driven entirely
     * by the claims here: an empty {@code powers} list with an {@code organizationIdentifier}
     * that doesn't match the tenant's {@code admin_organization_id} resolves to {@code LEAR};
     * matching org id plus the tenant's Onboarding/Execute domain power resolves to
     * {@code TENANT_ADMIN}.
     */
    protected String mintUserAccessToken(String tenantClaim, String organizationIdentifier,
                                         List<Map<String, Object>> powers) {
        long now = Instant.now().getEpochSecond();
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("iss", "http://localhost:" + port + "/issuer");
        payload.put("sub", "it-user-" + organizationIdentifier);
        payload.put("iat", now);
        payload.put("exp", now + 3600);
        ObjectNode mandator = payload.putObject("mandator");
        mandator.put("organizationIdentifier", organizationIdentifier);
        payload.set("power", objectMapper.valueToTree(powers));
        payload.put("tenant", tenantClaim);
        return jwtService.issueJWT(payload.toString());
    }

    /** {@link #mintUserAccessToken(String, String, List)} with no powers -- the shape that
     *  always resolves to {@code LEAR} (the operator role), since it never matches
     *  {@code TENANT_ADMIN}'s org+power requirement nor SysAdmin's power. */
    protected String mintOperatorAccessToken(String tenantClaim, String organizationIdentifier) {
        return mintUserAccessToken(tenantClaim, organizationIdentifier, List.of());
    }
}
