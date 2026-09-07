package es.in2.issuer.backend.issuance.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingIdTokenHeaderException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.DeliveryTrace;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.policy.service.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuedLogger;
import es.in2.issuer.backend.shared.domain.service.HolderDidFallbackAuditor;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.PayloadSchemaValidator;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import java.util.EnumSet;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuanceWorkflowImplTest {

    private static final String BASE_URL = "https://test.example/issuer";
    private static final String WALLET_URL = "https://test.example/wallet";
    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    /** One of the two types exempted from ADR-110 by AD-8: cnf sourced from the request holder_key. */
    private static final String EXEMPT_CONFIG_ID = "learcredential.machine.w3c.3";
    private static final String BEARER_TOKEN = "Bearer operator-access-token";
    private static final String EMAIL = "test@example.com";
    private static final String TENANT_ID = "sandbox";
    private static final int HYBRID_WALLET_TIMEOUT_SECONDS = 1;

    /**
     * Every call below simulates a request that already went through {@code TenantDomainWebFilter}
     * with a resolved tenant (EUD-170: {@code issueCredential} now fails closed without one).
     * Tenant-specific behavior itself (fail-closed, attribution) is covered separately below.
     */
    private static <T> Mono<T> withTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT_ID));
    }

    @Mock private IssuanceService issuanceService;
    @Mock private CredentialOfferService credentialOfferService;
    @Mock private IssuancePdpService issuancePdpService;
    @Mock private PayloadSchemaValidator payloadSchemaValidator;
    @Mock private CredentialProfileRegistry credentialProfileRegistry;
    @Mock private IssuanceMetrics issuanceMetrics;
    @Mock private CredentialIssuedLogger credentialIssuedLogger;
    @Mock private AuditService auditService;
    @Mock private GenericCredentialBuilder genericCredentialBuilder;
    @Mock private CredentialSignerWorkflow credentialSignerWorkflow;
    @Mock private StatusListWorkflow statusListWorkflow;
    @Mock private TenantConfigService tenantConfigService;
    @Mock private SchemaDeliveryCeiling schemaDeliveryCeiling;
    @Mock private HolderDidFallbackAuditor holderDidFallbackAuditor;

    @Spy
    private IssuanceProperties issuanceProperties =
            new IssuanceProperties(30, "0 0 2 * * *", 60, "0 */5 * * * ?", HYBRID_WALLET_TIMEOUT_SECONDS);

    @InjectMocks
    private IssuanceWorkflowImpl workflow;

    @BeforeEach
    void setUpDeliveryEligibility() {
        lenient().when(tenantConfigService.getStringOrDefault(anyString(), anyString()))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(1, String.class)));
        // Permissive ceiling by default so the pre-existing tests keep exercising what they were written
        // for; the tests that care about the ceiling override this stub explicitly.
        lenient().when(schemaDeliveryCeiling.resolveEligibleModes(anyString()))
                .thenReturn(EnumSet.allOf(DeliveryMode.class));
        // Identity by default (F2): bindHolderDid only matters to the tests asserting on
        // mandatee.id/cnf coherence for an AD-8 exempt type; everyone else just needs the dataSet
        // to survive the call unchanged.
        lenient().when(genericCredentialBuilder.bindHolderDid(anyString(), anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        // holderDidFallbackAuditor is @Mock only so @InjectMocks can wire it; delegate to a real
        // instance wrapping the same auditService mock, so tests keep exercising the real derivation
        // (and its audit-on-fallback behaviour) exactly as when this logic lived inline here.
        HolderDidFallbackAuditor realHolderDidFallbackAuditor = new HolderDidFallbackAuditor(auditService);
        lenient().when(holderDidFallbackAuditor.deriveFromJwkCnf(anyString(), anyString(), any()))
                .thenAnswer(invocation -> realHolderDidFallbackAuditor.deriveFromJwkCnf(
                        invocation.getArgument(0), invocation.getArgument(1), invocation.getArgument(2)));
    }

    // --- Existing tests ---

    @Test
    void executeShouldCompleteFullIssuanceFlowWithEmailDelivery() {
        JsonNode payload = new ObjectMapper().createObjectNode().put("name", "Test");
        UUID issuanceId = UUID.randomUUID();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri", null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(CONFIG_ID, payload, "id-token")).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), eq("authorization_code"),
                eq(EMAIL), eq("email"), eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertNotNull(response.credentialOfferUri());
                    assertNull(response.signedCredential());
                })
                .verifyComplete();

        verify(issuanceService).saveIssuance(any(Issuance.class));
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), eq("authorization_code"),
                eq(EMAIL), eq("email"), eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL));
        // A wallet offer is not an emitted credential — only the OID4VCI /credential endpoint
        // (where the wallet actually collects it) counts this leg.
        verify(credentialIssuedLogger, never()).logIssued(any());
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void executeShouldRejectUnknownCredentialType() {
        IssuanceRequest request = new IssuanceRequest("UnknownType", new ObjectMapper().createObjectNode(), null, EMAIL, null);
        when(credentialProfileRegistry.getByConfigurationId("UnknownType")).thenReturn(null);
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "idToken", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();
    }

    @Test
    void issueCredentialWithoutAuthorizationShouldSkipPdp() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("refresh-token-456").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "bootstrap-token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();

        verifyNoInteractions(issuancePdpService);
    }

    // --- New tests ---

    /**
     * FR-11. A mode that completed is reported as completed even when a sibling mode failed, and the
     * credential offer URI of a wallet mode that dispatched stays in the response: it is the QR the
     * operator can still hand over. Before this, a direct failure aborted the whole response and both
     * were lost, even though the offer had already been created and delivered.
     */
    @Test
    void hybridDeliveryWithFailedDirectShouldStillReportTheWalletModeAndKeepTheOfferUri() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,ui", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance oid4vciIssuance = Issuance.builder()
                .issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        // The direct leg dies where it actually died in production: reserving the status list entry.
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.error(new IllegalStateException("QTSP unavailable")));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertNull(response.signedCredential());
                    assertEquals("openid-credential-offer://offer-uri", response.credentialOfferUri());
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, deliveryResultFor(response, "direct").status());
                    // F3/W1: a closed code, never the raw "QTSP unavailable" -- that string can carry
                    // the signing provider's internal host/URL.
                    assertEquals("status_list_unavailable", deliveryResultFor(response, "direct").error());
                    assertEquals(DeliveryResult.DeliveryOutcome.DISPATCHED, deliveryResultFor(response, "ui").status());
                })
                .verifyComplete();

        verify(credentialIssuedLogger).logFailed(eq(CONFIG_ID), any());
    }

    /** F3/W1: the signing stage gets its own code, distinct from the status-list one above. */
    @Test
    void hybridDeliveryWithFailedDirectSigning_reportsSigningFailedCode() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,ui", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance oid4vciIssuance = Issuance.builder()
                .issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("Remote signing provider at https://qtsp.internal timed out")));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, deliveryResultFor(response, "direct").status());
                    assertEquals("signing_failed", deliveryResultFor(response, "direct").error());
                    assertEquals(DeliveryResult.DeliveryOutcome.DISPATCHED, deliveryResultFor(response, "ui").status());
                })
                .verifyComplete();
    }

    /** F3/W1: the persistence stage gets its own code -- an R2DBC failure can carry table/schema names. */
    @Test
    void hybridDeliveryWithFailedDirectPersistence_reportsPersistenceFailedCode() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,ui", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance oid4vciIssuance = Issuance.builder()
                .issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.error(new RuntimeException("relation \"tenant_cgcom.issuance\" violates constraint")));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, deliveryResultFor(response, "direct").status());
                    assertEquals("persistence_failed", deliveryResultFor(response, "direct").error());
                    assertEquals(DeliveryResult.DeliveryOutcome.DISPATCHED, deliveryResultFor(response, "ui").status());
                })
                .verifyComplete();
    }

    /**
     * FR-11, the other side of it: nothing was delivered, so this is not a partial outcome. The
     * original failure is re-raised and rendered as its own problem detail -- flattening it into a
     * body of failures would hide the cause behind a status with no explanation.
     */
    @Test
    void directOnlyDeliveryThatFailsShouldPropagateTheErrorRatherThanAPartialResponse() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.error(new IllegalStateException("QTSP unavailable")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectErrorMatches(e -> e instanceof IllegalStateException && "QTSP unavailable".equals(e.getMessage()))
                .verify();

        verifyNoInteractions(credentialOfferService);
    }

    /**
     * FR-11 for two wallet modes of the same offer: the email and the QR are separate modes. A bounced
     * email used to be propagated as an exception, which failed the {@code ui} mode too and threw away
     * a URI that had been built correctly.
     */
    @Test
    void emailAndUiDeliveryWithAFailedEmailShouldKeepUiDispatchedAndReturnTheOfferUri() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email,ui", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance oid4vciIssuance = Issuance.builder()
                .issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult(
                        "openid-credential-offer://offer-uri", "SMTP unavailable")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("openid-credential-offer://offer-uri", response.credentialOfferUri());
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, deliveryResultFor(response, "email").status());
                    assertEquals("SMTP unavailable", deliveryResultFor(response, "email").error());
                    assertEquals(DeliveryResult.DeliveryOutcome.DISPATCHED, deliveryResultFor(response, "ui").status());
                })
                .verifyComplete();
    }

    /**
     * The direct mode signs inside the issuance request, so it needs a caller token: the credential
     * signature demands one (a blank {@code SigningContext.token} is a {@code SigningException}) and
     * allocating a status list entry rejects a null one outright. Reading it from {@code X-Id-Token}
     * conflated an optional identity assertion with the caller's bearer credential, so every direct
     * issuance of a profile that requires no {@code X-Id-Token} -- which is all of them but
     * VerifiableCertification -- died on {@code NullPointerException: token cannot be null}.
     */
    @Test
    void directDeliveryWithoutAnIdTokenShouldStillSignUsingTheCallerBearerToken() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        StatusListEntry statusEntry = statusListEntry();
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), isNull())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), eq(BEARER_TOKEN), eq(BASE_URL)))
                .thenReturn(Mono.just(statusEntry));
        when(genericCredentialBuilder.injectCredentialStatus(eq("enriched-data-set"), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), eq("enriched-with-status"), eq(CONFIG_ID),
                anyString(), isNull(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, null, BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        // Both consumers get the bearer token, never the (absent) X-Id-Token.
        verify(statusListWorkflow).allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), eq(BEARER_TOKEN), eq(BASE_URL));
        verify(credentialSignerWorkflow).signCredential(eq(BEARER_TOKEN), anyString(), anyString(),
                anyString(), isNull(), anyString(), anyString());
    }

    @Test
    void directDeliveryShouldSignAndReturnCredentialWithValidStatusWhenValidFromIsPast() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        StatusListEntry statusEntry = statusListEntry();
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusEntry));
        when(genericCredentialBuilder.injectCredentialStatus(eq("enriched-data-set"), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), eq("enriched-with-status"), eq(CONFIG_ID),
                anyString(), isNull(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNull(response.credentialOfferUri());
                    assertNotNull(response.deliveryResults());
                    assertEquals(1, response.deliveryResults().size());
                    assertEquals("direct", response.deliveryResults().get(0).mode());
                    assertEquals(DeliveryResult.DeliveryOutcome.DELIVERED, response.deliveryResults().get(0).status());
                    assertNull(response.deliveryResults().get(0).error());
                })
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.VALID));
        verifyNoInteractions(credentialOfferService);
        verify(credentialIssuedLogger).logIssued(CONFIG_ID);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void directDeliveryShouldSignAndReturnCredentialWithIssuedStatusWhenValidFromIsFuture() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().plusSeconds(86400));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.ISSUED));
    }

    @Test
    void directDeliveryOfBoundTypeShouldBeRejectedByTheSchemaCeiling() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(true)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));
        doThrow(new DeliveryModeNotEligibleException(
                "Delivery mode 'direct' is not eligible for credential type '" + CONFIG_ID + "'"))
                .when(schemaDeliveryCeiling).validateWithinCeiling(eq(CONFIG_ID), any());

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(DeliveryModeNotEligibleException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeWithConfigButNoHolderKeyShouldFailWith400() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileExempt();

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + EXEMPT_CONFIG_ID), anyString()))
                .thenReturn(Mono.just("direct,email"));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(InvalidHolderKeyException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeNotEligibleShouldFailEvenWithValidHolderKey() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithCnf();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));
        doThrow(new DeliveryModeNotEligibleException(
                "Delivery mode 'direct' is not eligible for credential type '" + CONFIG_ID + "'"))
                .when(schemaDeliveryCeiling).validateWithinCeiling(eq(CONFIG_ID), any());

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(DeliveryModeNotEligibleException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeWithHolderKeyShouldSignWithCnfAndPersist() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileExempt();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + EXEMPT_CONFIG_ID), anyString()))
                .thenReturn(Mono.just("direct,email,ui"));
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), eq("enriched-with-status"), eq(EXEMPT_CONFIG_ID),
                anyString(), anyMap(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> cnfCaptor = ArgumentCaptor.forClass(Map.class);
        verify(credentialSignerWorkflow).signCredential(any(), any(), any(), any(),
                cnfCaptor.capture(), any(), any());
        assertNotNull(cnfCaptor.getValue());
        assertTrue(cnfCaptor.getValue().containsKey("jwk"));
        verify(issuanceService).saveIssuance(any(Issuance.class));
        verifyNoInteractions(credentialOfferService);

        // F2: the direct leg derives the holder DID from the holder_key jwk and binds it into
        // mandatee.id, the same invariant the wallet leg already enforces from a key proof.
        verify(genericCredentialBuilder).bindHolderDid(eq("enriched-data-set"), argThat(did -> did.startsWith("did:key:z")));
    }

    // TD-09's derivation-fallback-audits case (holderDidFromCnf's private-method reflection test)
    // moved to HolderDidFallbackAuditorTest once that logic was extracted to the shared
    // HolderDidFallbackAuditor -- it's a public method there, so no reflection is needed any more.

    /**
     * Code-review W1 (F4 regression, S4). A future profile of the same machine family that
     * recovers proof_types_supported still matches HolderBindingExemption's prefix, but is no
     * longer unbound -- it now gets a real key proof through the wallet flow, and holder_key must
     * go back to being irrelevant for it. Without the {@code !profile.requiresHolderBinding()}
     * gate, this request would throw InvalidHolderKeyException for lacking a holder_key it no
     * longer needs, breaking every wallet-mode emission of that profile.
     */
    @Test
    void walletDeliveryOfExemptPrefixButNowBoundProfileShouldNotRequireHolderKey() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID issuanceId = UUID.randomUUID();
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(EXEMPT_CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(true)
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .proofTypesSupported(Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                        .proofSigningAlgValuesSupported(Set.of("ES256"))
                        .build()))
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri", null);

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                issuanceId.toString(), EXEMPT_CONFIG_ID, "authorization_code",
                EMAIL, "email", "refresh-token-123", BASE_URL, WALLET_URL))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        ArgumentCaptor<Issuance> issuanceCaptor = ArgumentCaptor.forClass(Issuance.class);
        verify(issuanceService).saveIssuance(issuanceCaptor.capture());
        assertNull(issuanceCaptor.getValue().getHolderCnf(), "no cnf should be built from a holder_key this profile no longer needs");
    }

    @Test
    void directDeliveryOfCnfRequiredTypeWithAmbiguousHolderKeyShouldFailWith400() {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode payload = mapper.createObjectNode();
        JsonNode ambiguous = mapper.createObjectNode()
                .put("kid", "did:key:z6Mk#key-1");
        ((com.fasterxml.jackson.databind.node.ObjectNode) ambiguous)
                .set("jwk", mapper.createObjectNode().put("kty", "EC"));
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "direct", EMAIL, null, ambiguous);
        CredentialProfile profile = profileExempt();

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + EXEMPT_CONFIG_ID), anyString()))
                .thenReturn(Mono.just("direct,email,ui"));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(InvalidHolderKeyException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    /**
     * Code-review F1a: a bare kid/x5c carries no key material this path can validate or bind to
     * mandatee.id (no wallet, no key proof), so it must be rejected the same way an ambiguous or
     * malformed holder_key is -- not silently accepted the way HolderKey.fromJson accepts it for the
     * (unrelated) OID4VCI proof path.
     */
    @Test
    void directDeliveryOfCnfRequiredTypeWithKidHolderKeyShouldFailWith400() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        JsonNode kidOnly = new ObjectMapper().createObjectNode().put("kid", "did:key:z6Mk#key-1");
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "direct", EMAIL, null, kidOnly);
        CredentialProfile profile = profileExempt();

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + EXEMPT_CONFIG_ID), anyString()))
                .thenReturn(Mono.just("direct,email,ui"));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(InvalidHolderKeyException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeWithX5cHolderKeyShouldFailWith400() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        JsonNode x5cOnly = new ObjectMapper().createObjectNode()
                .set("x5c", new ObjectMapper().createArrayNode().add("MIIBcert"));
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "direct", EMAIL, null, x5cOnly);
        CredentialProfile profile = profileExempt();

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + EXEMPT_CONFIG_ID), anyString()))
                .thenReturn(Mono.just("direct,email,ui"));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(InvalidHolderKeyException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfNonCnfTypeShouldNotInjectCnfEvenIfHolderKeyPresent() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithoutCnf();
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(),
                anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(credentialSignerWorkflow).signCredential(any(), any(), any(), any(), isNull(), any(), any());
    }

    @Test
    void walletOnlyDeliveryOfCnfRequiredTypeShouldNotRequireHolderKey() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID issuanceId = UUID.randomUUID();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithCnf();
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId)
                .credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri", null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), anyString(), eq(EMAIL), eq("email"),
                eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        verifyNoInteractions(credentialSignerWorkflow);
    }

    @Test
    void hybridDeliveryOfCnfRequiredTypeShouldSignDirectWithCnfAndDispatchWallet() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID issuanceId = UUID.randomUUID();
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "direct,email", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileExempt();
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId)
                .credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri", null);

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + EXEMPT_CONFIG_ID), anyString()))
                .thenReturn(Mono.just("direct,email,ui"));
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(),
                anyString(), anyMap(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(EXEMPT_CONFIG_ID), anyString(), eq(EMAIL), eq("email"),
                eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNotNull(response.credentialOfferUri());
                })
                .verifyComplete();

        verify(credentialOfferService).createAndDeliverCredentialOffer(
                any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeShouldFailClosedWhenSignerFails() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileExempt();

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + EXEMPT_CONFIG_ID), anyString()))
                .thenReturn(Mono.just("direct,email,ui"));
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(any(), any(), any(), any(), anyMap(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("signer down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(IllegalStateException.class)
                .verify();

        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeShouldFailClosedWhenPersistenceFails() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileExempt();

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + EXEMPT_CONFIG_ID), anyString()))
                .thenReturn(Mono.just("direct,email,ui"));
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(any(), any(), any(), any(), anyMap(), any(), any()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class)))
                .thenReturn(Mono.error(new IllegalStateException("db down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(IllegalStateException.class)
                .verify();
    }

    @Test
    void directDeliveryOfCnfRequiredTypeShouldFailClosedWhenEligibilityReadFails() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithCnf();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + CONFIG_ID), anyString()))
                .thenReturn(Mono.error(new IllegalStateException("config store down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(IllegalStateException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }


    @Test
    void issueCredentialShouldFailWithInvalidDeliveryModeWhenModeIsUnknown() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,carrier-pigeon", EMAIL, null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profileWithoutCnf());
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(InvalidDeliveryModeException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void issueCredentialShouldFailWithInvalidDeliveryModeWhenModeIsBlank() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "   ", EMAIL, null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profileWithoutCnf());
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(InvalidDeliveryModeException.class)
                .verify();

        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void issueCredentialShouldRejectModeDisabledByTenantConfiguration() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profileWithoutCnf());
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + CONFIG_ID), anyString()))
                .thenReturn(Mono.just("email,ui"));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(DeliveryModeNotEligibleException.class, ex);
                    // The tenant narrowed the ceiling to email,ui: the message must report that
                    // effective set, not the wider schema ceiling (direct,email,ui), or callers are
                    // misled about what to retry with.
                    assertEquals("Delivery mode 'direct' is not eligible for credential type '"
                            + CONFIG_ID + "'. Eligible modes: email,ui", ex.getMessage());
                })
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
    }

    @Test
    void issueCredentialShouldReportNoneEligibleWhenTenantConfigurationSharesNothingWithCeiling() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profileWithoutCnf());
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        // Ceiling narrowed to wallet-only modes (a bound type), and a stale tenant configuration
        // listing only "direct" -- it shares nothing with the ceiling, so the effective eligible set
        // that ends up in the error message is empty.
        when(schemaDeliveryCeiling.resolveEligibleModes(CONFIG_ID))
                .thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));
        when(tenantConfigService.getStringOrDefault(eq("issuer.delivery.modes." + CONFIG_ID), anyString()))
                .thenReturn(Mono.just("direct"));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(DeliveryModeNotEligibleException.class, ex);
                    assertEquals("Delivery mode 'email' is not eligible for credential type '"
                            + CONFIG_ID + "'. Eligible modes: none", ex.getMessage());
                })
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
    }

    @Test
    void combinedDirectAndEmailDeliveryShouldRunBothFlowsAndReturnBothResults() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        UUID oid4vciIssuanceId = UUID.randomUUID();
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(oid4vciIssuanceId).credentialOfferRefreshToken("rt-123").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        // Direct flow mocks
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        // OID4VCI flow mocks
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(oid4vciIssuanceId.toString()), any(), any(), any(), eq("email"), eq("rt-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNotNull(response.credentialOfferUri());
                    assertNotNull(response.deliveryResults());
                    assertTrue(response.deliveryResults().stream().anyMatch(r ->
                            "direct".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.DELIVERED));
                    assertTrue(response.deliveryResults().stream().anyMatch(r ->
                            "email".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.DISPATCHED));
                })
                .verifyComplete();

        verify(issuanceService, times(2)).saveIssuance(any(Issuance.class));
        verify(credentialSignerWorkflow).signCredential(any(), any(), any(), any(), any(), any(), any());
        verify(credentialOfferService).createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any());
        // Exactly one credential is emitted here (the direct leg); the wallet leg only creates a
        // DRAFT + sends an offer, so it must not add a second increment.
        verify(credentialIssuedLogger, times(1)).logIssued(CONFIG_ID);
    }

    @Test
    void uiDeliveryShouldReturnCredentialOfferUriWithoutSignedCredential() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "ui", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-ui").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), any(), eq(EMAIL), eq("ui"), eq("rt-ui"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertNotNull(response.credentialOfferUri());
                    assertNull(response.signedCredential());
                    assertNotNull(response.deliveryResults());
                    assertEquals(1, response.deliveryResults().size());
                    assertEquals("ui", response.deliveryResults().get(0).mode());
                    assertEquals(DeliveryResult.DeliveryOutcome.DISPATCHED, response.deliveryResults().get(0).status());
                })
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.DRAFT));
        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow);
        verify(credentialIssuedLogger, never()).logIssued(any());
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void bootstrapWithDirectDeliveryShouldIgnoreDirectAndRunOid4vciFlow() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-bootstrap").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "bootstrap-token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNull(response.signedCredential()))
                .verifyComplete();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow);
        verify(credentialOfferService).createAndDeliverCredentialOffer(any(), any(), any(), any(), eq("email"), any(), any(), any());
        // Bootstrap strips "direct" and never signs anything.
        verify(credentialIssuedLogger, never()).logIssued(any());
    }

    @Test
    void issueCredentialShouldFailWithMissingIdTokenWhenProfileRequiresIt() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "VerifiableCertification"))
                        .build())
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .rules(List.of("RequireCertificationIssuance"))
                        .build())
                .build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, null, BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(MissingIdTokenHeaderException.class)
                .verify();
    }

    @Test
    void issueCredentialWithoutAuthorizationShouldUseDefaultEmailDeliveryWhenDeliveryIsNull() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, null, EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-null-delivery").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "bootstrap-token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        verifyNoInteractions(issuancePdpService);
    }

    @Test
    void issueCredentialShouldPassValidationWhenProfileRequiresIdTokenAndTokenIsProvided() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "VerifiableCertification"))
                        .build())
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .rules(List.of("RequireCertificationIssuance"))
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-cert").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();
    }

    @Test
    void validateRequestShouldPassWhenIssuancePolicyHasNullRules() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .rules(null)
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-null-rules").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();
    }

    @Test
    void directDeliveryShouldReturnValidStatusWhenValidFromIsNull() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = CredentialBuildResult.builder()
                .credentialDataSet("{\"credential\":\"data\"}")
                .subject("did:key:subject")
                .organizationIdentifier("ORGID")
                .validFrom(null)
                .validUntil(null)
                .build();
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.VALID));
    }

    @Test
    void directDeliveryShouldUseDefaultJwtVcJsonFormatWhenProfileFormatIsNull() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format(null)
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.BITSTRING_VC),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(statusListWorkflow).allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.BITSTRING_VC),
                anyString(), anyString(), eq(BASE_URL));
    }

    @Test
    void directDeliveryShouldUseTokenJwtStatusFormatForDcSdJwtCredential() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("dc+sd-jwt")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.TOKEN_JWT),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(statusListWorkflow).allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.TOKEN_JWT),
                anyString(), anyString(), eq(BASE_URL));
    }

    @Test
    void oid4vciIssuanceShouldUseProvidedGrantTypeWhenNotNull() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, "urn:ietf:params:oauth:grant-type:pre-authorized_code");
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-grant").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                any(), eq(CONFIG_ID), eq("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                eq(EMAIL), eq("email"), eq("rt-grant"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        verify(credentialOfferService).createAndDeliverCredentialOffer(
                any(), any(), eq("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                any(), any(), any(), any(), any());
    }

    @Test
    void validateRequestShouldPassWhenIssuancePolicyHasRulesWithoutRequiredRule() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .rules(List.of("SomeOtherRule"))
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-other-rule").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();
    }

    @Test
    void directIssuanceOfDcSdJwtProfileShouldPersistTheProfileCredentialFormat() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("dc+sd-jwt")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .sdJwt(CredentialProfile.SdJwtConfig.builder()
                        .vct("LEARCredentialEmployee")
                        .sdAlg("sha-256")
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.TOKEN_JWT),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), eq("dc+sd-jwt")))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), eq(CONFIG_ID),
                eq("dc+sd-jwt"), isNull(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-sd-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-sd-jwt", response.signedCredential()))
                .verifyComplete();

        // AC-04: the SD-JWT VC credential is persisted with the profile's format, not a
        // default format or another branch's.
        verify(issuanceService).saveIssuance(argThat(i -> "dc+sd-jwt".equals(i.getCredentialFormat())));
    }

    @Test
    void oid4vciIssuanceShouldPersistTheCatalogueConfigurationIdAsCredentialType() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialOfferRefreshToken("rt-conformance")
                .build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        // AC-04: the credential_configuration_id sent matches exactly the resolved catalog
        // profile -- no intermediate rewrites on the persisted entity.
        verify(issuanceService).saveIssuance(argThat(i -> CONFIG_ID.equals(i.getCredentialType())));
    }

    @Test
    void hybridDeliveryWalletFailureShouldKeepDirectDelivered() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unavailable")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNull(response.credentialOfferUri());
                    DeliveryResult direct = deliveryResultFor(response, "direct");
                    DeliveryResult email = deliveryResultFor(response, "email");
                    assertEquals(DeliveryResult.DeliveryOutcome.DELIVERED, direct.status());
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, email.status());
                    assertNotNull(email.error());
                })
                .verifyComplete();

        // Mono.zip isolation: the wallet leg's failure (swallowed by
        // performOid4VciIssuanceResilient) must not affect the direct leg's counter.
        verify(credentialIssuedLogger).logIssued(CONFIG_ID);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void hybridDeliveryWalletTimeoutShouldKeepDirectDelivered() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        // Wallet path never completes within the hybrid budget (HYBRID_WALLET_TIMEOUT_SECONDS = 1s).
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("offer", null)).delayElement(Duration.ofSeconds(30)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    DeliveryResult email = deliveryResultFor(response, "email");
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, email.status());
                    assertEquals("wallet_delivery_timeout", email.error());
                    assertEquals(DeliveryResult.DeliveryOutcome.DELIVERED, deliveryResultFor(response, "direct").status());
                })
                .verifyComplete();

        verify(credentialIssuedLogger).logIssued(CONFIG_ID);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void directDeliverySignerFailureShouldFailClosed() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("QTSP down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(RuntimeException.class)
                .verify();

        verify(issuanceService, never()).saveIssuance(any());
        verify(credentialIssuedLogger).logFailed(eq(CONFIG_ID), any());
        verify(credentialIssuedLogger, never()).logIssued(any());
    }

    @Test
    void hybridDirectResultShouldBeIdenticalForEmailAndUiChannels() {
        String signedEmail = runHybridAndCaptureSignedCredential("direct,email", "email");
        String signedUi = runHybridAndCaptureSignedCredential("direct,ui", "ui");

        assertEquals("signed-jwt", signedEmail);
        assertEquals(signedEmail, signedUi);
    }

    private String runHybridAndCaptureSignedCredential(String delivery, String expectedWalletChannel) {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, delivery, EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), eq(expectedWalletChannel), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri", null)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        IssuanceResponse response = withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)).block();
        assertNotNull(response);
        verify(credentialOfferService).createAndDeliverCredentialOffer(any(), any(), any(), any(), eq(expectedWalletChannel), any(), any(), any());
        return response.signedCredential();
    }

    @Test
    void directDeliveryShouldInjectStatusPointerAndPersistBeforeDelivered() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(eq("enriched-data-set"), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), eq("enriched-with-status"), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals(DeliveryResult.DeliveryOutcome.DELIVERED,
                        deliveryResultFor(response, "direct").status()))
                .verifyComplete();

        verify(statusListWorkflow).allocateEntry(eq(StatusPurpose.REVOCATION), any(), anyString(), anyString(), eq(BASE_URL));
        verify(genericCredentialBuilder).injectCredentialStatus(eq("enriched-data-set"), any(), anyString());
        verify(issuanceService).saveIssuance(argThat(i ->
                i.getCredentialStatus() == CredentialStatusEnum.VALID
                        && "enriched-with-status".equals(i.getCredentialDataSet())));
    }

    @Test
    void directDeliveryPersistenceFailureShouldFailClosed() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.error(new RuntimeException("DB down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(RuntimeException.class)
                .verify();

        verify(credentialIssuedLogger).logFailed(eq(CONFIG_ID), any());
        verify(credentialIssuedLogger, never()).logIssued(any());
    }

    @Test
    void auditDeliveryShouldIncludeDeliveryResultsTenantAndNoRecipientEmail() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<DeliveryTrace> captor = ArgumentCaptor.forClass(DeliveryTrace.class);
        verify(auditService).auditDelivery(captor.capture());
        DeliveryTrace trace = captor.getValue();
        assertEquals(TENANT_ID, trace.tenantId());
        assertEquals("p", trace.processId());
        assertFalse(trace.hasFailure());
        assertTrue(trace.results().stream().anyMatch(r ->
                "direct".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.DELIVERED));
        assertFalse(trace.toString().contains(EMAIL), "delivery trace must not leak recipient email");
    }

    @Test
    void auditDeliveryShouldEmitFailedTraceOnSignerError() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("QTSP down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(RuntimeException.class)
                .verify();

        ArgumentCaptor<DeliveryTrace> captor = ArgumentCaptor.forClass(DeliveryTrace.class);
        verify(auditService).auditDelivery(captor.capture());
        DeliveryTrace trace = captor.getValue();
        assertEquals(TENANT_ID, trace.tenantId());
        assertTrue(trace.hasFailure());
        assertTrue(trace.results().stream().anyMatch(r ->
                r.status() == DeliveryResult.DeliveryOutcome.FAILED && "indeterminate_result".equals(r.error())));
    }

    @Test
    void issueCredentialShouldFailClosedWhenTenantIsNotResolved() {
        // Given (AC-05/ES-02): no tenant in the Reactor context, unlike every other test in this class
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);

        // When / Then
        StepVerifier.create(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL))
                .expectError(TenantNotResolvedException.class)
                .verify();

        // Nothing that runs after tenant resolution (deferred via Mono.defer) ever executed, and
        // no trace was emitted against a default tenant. (credentialProfileRegistry is excluded:
        // validateRequest(...) is evaluated eagerly as a plain method argument before the reactive
        // chain subscribes, so it always runs regardless of the tenant guard's outcome -- a
        // pre-existing trait of this method, unrelated to fail-closed behavior.)
        verifyNoInteractions(auditService, payloadSchemaValidator,
                issuancePdpService, genericCredentialBuilder, credentialSignerWorkflow,
                issuanceService, credentialOfferService);
    }

    @Test
    void auditDeliveryShouldReflectFailureWhenWalletLegFailsInHybridDelivery() {
        // Given (AC-03/EC-02): hybrid delivery, wallet leg fails, direct leg delivers
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unavailable")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<DeliveryTrace> captor = ArgumentCaptor.forClass(DeliveryTrace.class);
        verify(auditService).auditDelivery(captor.capture());
        DeliveryTrace trace = captor.getValue();
        assertTrue(trace.hasFailure(), "one failed leg in a hybrid delivery must mark the trace as a failure (AC-03)");
        assertTrue(trace.results().stream().anyMatch(r ->
                "direct".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.DELIVERED));
        assertTrue(trace.results().stream().anyMatch(r ->
                "email".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.FAILED));
    }

    @Test
    void auditDeliveryShouldContainOnlyWalletModeForWalletOnlyDelivery() {
        // Given (EC-01): wallet-only delivery must not fabricate a direct entry
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID issuanceId = UUID.randomUUID();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri", null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(CONFIG_ID, payload, "id-token")).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), eq("authorization_code"),
                eq(EMAIL), eq("email"), eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<DeliveryTrace> captor = ArgumentCaptor.forClass(DeliveryTrace.class);
        verify(auditService).auditDelivery(captor.capture());
        DeliveryTrace trace = captor.getValue();
        assertEquals(1, trace.results().size());
        assertEquals("email", trace.results().iterator().next().mode());
        assertFalse(trace.hasFailure());
    }

    @Test
    void issueCredentialShouldCompleteSuccessfullyEvenWhenAuditChannelThrows() {
        // Given (ES-03/ES-04): the credential is already delivered before the audit call is made
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq(BEARER_TOKEN), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));
        doThrow(new RuntimeException("AUDIT channel down")).when(auditService).auditDelivery(any());

        // Then: a broken audit channel must not surface as a failure of the response the operator receives.
        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();
    }

    // --- Helpers ---

    private DeliveryResult deliveryResultFor(IssuanceResponse response, String mode) {
        assertNotNull(response.deliveryResults());
        return response.deliveryResults().stream()
                .filter(r -> mode.equals(r.mode()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No delivery result for mode " + mode));
    }

    private CredentialProfile profileWithoutCnf() {
        return CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();
    }

    private CredentialProfile profileWithCnf() {
        return CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(true)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();
    }


    /**
     * AC-12 / AD-8. The exception is not gated on the direct mode: with {@code proof_types_supported}
     * gone, no key proof arrives through the wallet flow either, so the request holder_key is the only
     * source of cnf there is -- for every delivery mode alike.
     *
     * <p>The wallet legs sign in a later request, at the Credential Endpoint, so the assertion is that
     * the cnf is persisted on the issuance row: consuming the holder key here and dropping it would
     * leave that request with no cnf to write and fail the signing step instead.
     */
    @Test
    void walletOnlyDeliveryOfExemptTypeShouldStillBuildCnfFromTheRequestHolderKey() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "email", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileExempt();
        UUID issuanceId = UUID.randomUUID();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder()
                .issuanceId(issuanceId).credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri", null);

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(EXEMPT_CONFIG_ID), anyString(),
                eq(EMAIL), eq("email"), anyString(), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<Issuance> issuanceCaptor = ArgumentCaptor.forClass(Issuance.class);
        verify(issuanceService).saveIssuance(issuanceCaptor.capture());
        String persistedCnf = issuanceCaptor.getValue().getHolderCnf();
        assertNotNull(persistedCnf, "holder cnf must survive to the Credential Endpoint");
        assertTrue(persistedCnf.contains("jwk"));
        assertTrue(persistedCnf.contains("P-256"));
    }

    /**
     * AC-10. A bound type derives its cnf from the key proof at the Credential Endpoint, so nothing
     * about the request holder key may be persisted for it -- a stored cnf would be read back as a
     * binding the holder never proved.
     */
    @Test
    void walletDeliveryOfNonExemptTypeShouldNotPersistAnyHolderCnf() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithCnf();
        UUID issuanceId = UUID.randomUUID();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder()
                .issuanceId(issuanceId).credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri", null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), anyString(),
                eq(EMAIL), eq("email"), anyString(), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<Issuance> issuanceCaptor = ArgumentCaptor.forClass(Issuance.class);
        verify(issuanceService).saveIssuance(issuanceCaptor.capture());
        assertNull(issuanceCaptor.getValue().getHolderCnf());
    }

    /**
     * AC-13. For the exempted types the holder key is mandatory in every mode: a missing one is a bad
     * request, never an issuance that silently drops the cnf.
     */
    @Test
    void walletOnlyDeliveryOfExemptTypeWithoutHolderKeyShouldFailWith400() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(EXEMPT_CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileExempt();

        when(credentialProfileRegistry.getByConfigurationId(EXEMPT_CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(EXEMPT_CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(EXEMPT_CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BEARER_TOKEN, BASE_URL, WALLET_URL)))
                .expectError(InvalidHolderKeyException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    private CredentialProfile profileExempt() {
        return CredentialProfile.builder()
                .credentialConfigurationId(EXEMPT_CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(true)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialMachine"))
                        .build())
                .build();
    }

    // A real P-256 public point: Nimbus (EUD-168 F1) validates x/y are actually on the declared
    // curve, so an arbitrary placeholder string is not a valid fixture here.
    private JsonNode holderKeyJwk() {
        ObjectMapper m = new ObjectMapper();
        return m.createObjectNode().set("jwk",
                m.createObjectNode().put("kty", "EC").put("crv", "P-256")
                        .put("x", "jIoYu_tVQYeSX_WAXLz219rFkqGV6c4FTb4_cQdOaQg")
                        .put("y", "BBkUW2sUZX2kW7keQ-qZV3PCKCLOZesPpszoNGciDL4"));
    }

    private CredentialBuildResult buildResult(Instant validFrom) {
        return new CredentialBuildResult(
                "{\"credential\":\"data\"}",
                "did:key:subject",
                "ORGID",
                Timestamp.from(validFrom),
                Timestamp.from(validFrom.plusSeconds(86400 * 365)));
    }

    private StatusListEntry statusListEntry() {
        return StatusListEntry.builder()
                .id("https://status-list/1#42")
                .type("BitstringStatusListEntry")
                .statusPurpose(StatusPurpose.REVOCATION)
                .statusListIndex("42")
                .statusListCredential("https://status-list/1")
                .build();
    }
}
