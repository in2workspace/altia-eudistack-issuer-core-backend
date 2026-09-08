package es.in2.issuer.backend.issuance.infrastructure.it;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.issuance.application.workflow.impl.IssuanceWorkflowImpl;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceController;
import es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceExceptionHandler;
import es.in2.issuer.backend.issuance.infrastructure.controller.IssuanceHttpEnvelopeMapper;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.policy.service.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuedLogger;
import es.in2.issuer.backend.shared.domain.service.HolderDidFallbackAuditor;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.PayloadSchemaValidator;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * End-to-end rejection tests for the schema delivery ceiling (ADR-110, EUD-168), against the real
 * HTTP endpoint ({@code POST /api/v1/issuances}) with the real business rule chain.
 *
 * <p>Unlike {@code IssuanceControllerTest}, {@code IssuanceWorkflow} is not mocked here: the whole
 * point is exercising {@link SchemaDeliveryCeiling} and {@link CredentialProfileRegistry} for real,
 * loaded from the classpath profile fixture, exactly as {@link IssuanceWorkflowImpl} wires them in
 * production. Everything the ceiling check runs <em>before</em> -- {@link PayloadSchemaValidator},
 * {@link IssuancePdpService} -- and everything a rejected request must never reach -- signing, status
 * list, persistence, the Wallet offer trigger -- are mocked, because those are the actual I/O
 * boundaries {@link IssuanceWorkflowImpl} injects.
 *
 * <p>No Spring context, no Testcontainers (TD-07): {@code IssuanceController} and
 * {@code IssuanceWorkflowImpl} are constructed by hand and bound directly via
 * {@code WebTestClient.bindToController}, with a stub {@link WebFilter} standing in for
 * {@code TenantDomainWebFilter} (which itself needs a DB-backed tenant registry lookup this test has
 * no reason to pull in).
 */
class DirectDeliveryCeilingTest {

    private static final String ISSUANCES_PATH = "/api/v1/issuances";
    private static final String BEARER_TOKEN = "Bearer operator-access-token";
    private static final String TENANT = "sandbox";
    private static final String PUBLIC_ISSUER_BASE_URL = "https://issuer.example.com";
    private static final String PUBLIC_WALLET_BASE_URL = "https://issuer.example.com/wallet";

    // The one real profile fixture on the test classpath (src/test/resources/credentials/profiles):
    // learcredential.employee.w3c.4, which declares proof_types_supported and is therefore bound
    // (requiresHolderBinding() == true) -- exactly the shape the ceiling must reject "direct" for.
    private static final String BOUND_CONFIG_ID = "learcredential.employee.w3c.4";

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    private PayloadSchemaValidator payloadSchemaValidator;
    private IssuancePdpService issuancePdpService;
    private IssuanceService issuanceService;
    private CredentialOfferService credentialOfferService;
    private CredentialSignerWorkflow credentialSignerWorkflow;
    private StatusListWorkflow statusListWorkflow;
    private GenericCredentialBuilder genericCredentialBuilder;
    private WebTestClient webTestClient;

    @BeforeEach
    void setUp() {
        ResourcePatternResolver resourcePatternResolver = new PathMatchingResourcePatternResolver();
        CredentialProfileRegistry credentialProfileRegistry = new CredentialProfileRegistry(
                OBJECT_MAPPER, resourcePatternResolver, "classpath:credentials/profiles");
        SchemaDeliveryCeiling schemaDeliveryCeiling = new SchemaDeliveryCeiling(credentialProfileRegistry);

        payloadSchemaValidator = mock(PayloadSchemaValidator.class);
        issuancePdpService = mock(IssuancePdpService.class);
        issuanceService = mock(IssuanceService.class);
        credentialOfferService = mock(CredentialOfferService.class);
        credentialSignerWorkflow = mock(CredentialSignerWorkflow.class);
        statusListWorkflow = mock(StatusListWorkflow.class);
        genericCredentialBuilder = mock(GenericCredentialBuilder.class);
        TenantConfigService tenantConfigService = mock(TenantConfigService.class);
        AuditService auditService = mock(AuditService.class);
        CredentialIssuedLogger credentialIssuedLogger = mock(CredentialIssuedLogger.class);
        IssuanceMetrics issuanceMetrics = mock(IssuanceMetrics.class);
        IssuanceProperties issuanceProperties = new IssuanceProperties(30, "0 0 2 * * *", 60, "0 */5 * * * ?", 30);
        // Rejection happens before the direct leg ever runs (the ceiling check is upstream of
        // performIssuanceFlow), so this collaborator is never exercised by these tests.
        HolderDidFallbackAuditor holderDidFallbackAuditor = mock(HolderDidFallbackAuditor.class);

        // The two gates the ceiling check runs after: both must clear for the request to reach
        // SchemaDeliveryCeiling at all. Real objects have nothing to say here -- they are the
        // I/O boundaries this test stubs, not the rule under test.
        when(payloadSchemaValidator.validate(any(), any())).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(any(), any(), any())).thenReturn(Mono.empty());

        IssuanceWorkflowImpl issuanceWorkflow = new IssuanceWorkflowImpl(
                issuanceService,
                credentialOfferService,
                issuancePdpService,
                payloadSchemaValidator,
                credentialProfileRegistry,
                issuanceMetrics,
                credentialIssuedLogger,
                auditService,
                genericCredentialBuilder,
                credentialSignerWorkflow,
                statusListWorkflow,
                tenantConfigService,
                issuanceProperties,
                schemaDeliveryCeiling,
                holderDidFallbackAuditor
        );

        UrlResolver urlResolver = mock(UrlResolver.class);
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);

        IssuanceController controller = new IssuanceController(
                issuanceWorkflow,
                mock(IssuanceService.class),
                mock(AccessTokenService.class),
                mock(RevocationWorkflow.class),
                urlResolver,
                new IssuanceHttpEnvelopeMapper()
        );

        // Stands in for TenantDomainWebFilter (which resolves the tenant against tenant_registry --
        // real I/O this test has no business exercising): writes the same context key the production
        // filter writes, so IssuanceWorkflowImpl's requireResolvedTenant() guard sees a resolved tenant.
        WebFilter tenantContextFilter = (exchange, chain) ->
                chain.filter(exchange).contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));

        webTestClient = WebTestClient.bindToController(controller)
                .controllerAdvice(new IssuanceExceptionHandler(new ErrorResponseFactory()))
                .webFilter(tenantContextFilter)
                .build();
    }

    /**
     * AC-03: a request for a bound credential type outside the schema ceiling ("direct" for a type
     * whose schema declares {@code proof_types_supported}) never reaches signing, status list
     * reservation, persistence or the Wallet offer trigger -- {@link SchemaDeliveryCeiling} rejects it
     * before {@code IssuanceWorkflowImpl#executeIssuanceForModes} runs at all.
     */
    @Test
    void createIssuance_DirectDeliveryOutsideCeiling_NeverReachesSigningStatusListPersistenceOrWallet()
            throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest(BOUND_CONFIG_ID, "direct");

        webTestClient.post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(OBJECT_MAPPER.writeValueAsString(request))
                .exchange()
                .expectStatus().isEqualTo(409);

        verifyNoInteractions(credentialSignerWorkflow);
        verifyNoInteractions(statusListWorkflow);
        verifyNoInteractions(issuanceService);
        verifyNoInteractions(credentialOfferService);
        verifyNoInteractions(genericCredentialBuilder);
    }

    /**
     * ES-03: the rejection is a 409 with an actionable real response body -- naming the rejected mode,
     * the credential type and the modes that remain available -- produced by the real exception
     * mapping ({@link IssuanceExceptionHandler} + real {@code ErrorResponseFactory}), not a stub.
     */
    @Test
    void createIssuance_DirectDeliveryOutsideCeiling_Returns409WithActionableRealBody()
            throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest(BOUND_CONFIG_ID, "direct");

        webTestClient.post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(OBJECT_MAPPER.writeValueAsString(request))
                .exchange()
                .expectStatus().isEqualTo(409)
                .expectBody()
                .jsonPath("$.type").isEqualTo("delivery_mode_not_eligible")
                .jsonPath("$.status").isEqualTo(409)
                .jsonPath("$.detail").value(org.hamcrest.Matchers.allOf(
                        org.hamcrest.Matchers.containsString("'direct'"),
                        org.hamcrest.Matchers.containsString(BOUND_CONFIG_ID),
                        org.hamcrest.Matchers.containsString("email"),
                        org.hamcrest.Matchers.containsString("ui")))
                .jsonPath("$.instance").isNotEmpty();
    }

    /**
     * ES-01: an unknown delivery mode is rejected as a 400 {@code invalid_request} before the ceiling
     * (or any other business rule) is even evaluated -- {@code DeliveryMode.parse} fails first.
     *
     * <p>Fixture is letters-only (no hyphen): this test targets {@code DeliveryMode.parse}'s rejection
     * specifically, not the DTO-level {@code @Pattern} added for TD-06 -- a hyphenated value like the
     * previous {@code "carrier-pigeon"} would now be rejected one layer earlier by Bean Validation,
     * which this hand-wired {@code bindToController} harness (no default WebFlux exception handling,
     * unlike the full app context) has no handler for.
     */
    @Test
    void createIssuance_InvalidDeliveryMode_Returns400InvalidRequest() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest(BOUND_CONFIG_ID, "carrierpigeon");

        webTestClient.post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(OBJECT_MAPPER.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.type").isEqualTo("invalid_request")
                .jsonPath("$.status").isEqualTo(400)
                .jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("carrierpigeon"));

        verifyNoInteractions(credentialSignerWorkflow);
        verifyNoInteractions(statusListWorkflow);
        verifyNoInteractions(issuanceService);
        verifyNoInteractions(credentialOfferService);
    }

    private IssuanceRequest buildIssuanceRequest(String credentialConfigurationId, String delivery) {
        return IssuanceRequest.builder()
                .credentialConfigurationId(credentialConfigurationId)
                .payload(OBJECT_MAPPER.createObjectNode().put("key", "value"))
                .delivery(delivery)
                .email("test@example.com")
                .build();
    }
}
