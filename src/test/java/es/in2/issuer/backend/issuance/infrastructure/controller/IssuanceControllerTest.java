package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dtos.UpdateIssuanceStatusRequest;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceSummary;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockitoBean(types = ReactiveAuthenticationManager.class)
@WebFluxTest(IssuanceController.class)
@Import({IssuanceExceptionHandler.class, IssuanceHttpEnvelopeMapper.class})
class IssuanceControllerTest {

    private static final String ISSUANCES_PATH = "/api/v1/issuances";
    private static final String BEARER_TOKEN = "Bearer operator-access-token";
    private static final String PUBLIC_ISSUER_BASE_URL = "https://issuer.example.com";
    private static final String PUBLIC_WALLET_BASE_URL = "https://issuer.example.com/wallet";

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private ErrorResponseFactory errorResponseFactory;

    @MockitoBean
    private NonceService nonceService;

    @MockitoBean
    private IssuanceWorkflow issuanceWorkflow;

    @MockitoBean
    private IssuanceService issuanceService;

    @MockitoBean
    private AccessTokenService accessTokenService;

    @MockitoBean
    private RevocationWorkflow revocationWorkflow;

    @MockitoBean
    private IssuanceMetrics issuanceMetrics;

    @MockitoBean
    private TenantRegistryService tenantRegistryService;

    @MockitoBean
    private UrlResolver urlResolver;

    /**
     * EUD-167 D-6/D-5 (AD-1 B) supersedes EUD-168 AD-11's 500: a hybrid issuance whose direct mode
     * failed while the wallet mode dispatched is a mixed outcome, reported as HTTP 207 Multi-Status
     * (RFC 4918 §11.1/§13) with per-mode results and the credential offer URI intact -- not a 500.
     */
    @Test
    void createIssuance_WhenDirectDeliveryFailedInHybrid_Returns207WithPerModeResultsAndOfferUri()
            throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fabc";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL), eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .deliveryResults(List.of(
                                DeliveryResult.failed("direct", DeliveryErrorCode.SIGNING_FAILED.value()),
                                DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.MULTI_STATUS)
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("direct")
                .jsonPath("$.responses[0].status").isEqualTo(503)
                .jsonPath("$.responses[0].error.type").isEqualTo("signing_failed")
                .jsonPath("$.responses[0].error.title").isEqualTo("Signing failed")
                .jsonPath("$.responses[0].body").doesNotExist()
                .jsonPath("$.responses[1].channel").isEqualTo("ui")
                .jsonPath("$.responses[1].status").isEqualTo(200)
                .jsonPath("$.responses[1].body.credential_offer_uri").isEqualTo(credentialOfferUri)
                .jsonPath("$.responses[1].error").doesNotExist();
    }

    /**
     * The mirror case: a wallet mode failed while the direct mode delivered. Also a mixed outcome
     * under D-5's general rule (at least one 2xx, at least one failure => 207) -- previously 200 under
     * AD-11, which only looked at whether the *direct* mode failed.
     */
    @Test
    void createIssuance_WhenOnlyAWalletModeFailed_Returns207WithPerModeResults() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fabc";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL), eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .deliveryResults(List.of(
                                DeliveryResult.failed("email", DeliveryErrorCode.DELIVERY_FAILED.value()),
                                DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.MULTI_STATUS)
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("email")
                .jsonPath("$.responses[0].status").isEqualTo(503)
                .jsonPath("$.responses[0].error.type").isEqualTo("delivery_failed")
                .jsonPath("$.responses[1].channel").isEqualTo("ui")
                .jsonPath("$.responses[1].status").isEqualTo(200)
                .jsonPath("$.responses[1].body.credential_offer_uri").isEqualTo(credentialOfferUri);
    }

    /**
     * Every requested channel failed (e.g. the wallet dependency is down for a wallet-only request,
     * so the direct leg was never attempted and assembleOutcome had nothing to re-raise). Not a mixed
     * outcome -- a genuine failure, reported as 500 instead of 200/202.
     */
    @Test
    void createIssuance_WhenAllChannelsFailed_Returns500() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL), eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .deliveryResults(List.of(
                                DeliveryResult.failed("email", DeliveryErrorCode.DELIVERY_FAILED.value()),
                                DeliveryResult.failed("ui", DeliveryErrorCode.WALLET_DELIVERY_TIMEOUT.value())))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().is5xxServerError()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("email")
                .jsonPath("$.responses[0].status").isEqualTo(503)
                .jsonPath("$.responses[0].error.type").isEqualTo("delivery_failed")
                // WALLET_DELIVERY_TIMEOUT maps to 504, distinct from the generic 503 (per-channel status).
                .jsonPath("$.responses[1].channel").isEqualTo("ui")
                .jsonPath("$.responses[1].status").isEqualTo(504)
                .jsonPath("$.responses[1].error.type").isEqualTo("wallet_delivery_timeout");
    }

    @Test
    void createIssuance_WhenCredentialOfferUriIsPresent_Returns200WithBody() throws JsonProcessingException {
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fcredential-offer%2Fabc123";
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL), eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .deliveryResults(List.of(DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("ui")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body.credential_offer_uri").isEqualTo(credentialOfferUri)
                .jsonPath("$.responses[0].body.signed_credential").doesNotExist();
    }

    @Test
    void createIssuance_WhenSignedCredentialIsPresent_Returns200WithBody() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String signedCredential = "signed-credential-value";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL), eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .signedCredential(signedCredential)
                        .deliveryResults(List.of(DeliveryResult.delivered("direct")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("direct")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body.signed_credential").isEqualTo(signedCredential)
                .jsonPath("$.responses[0].body.credential_offer_uri").doesNotExist();
    }

    @Test
    void createIssuance_Hybrid_Returns200WithDeliveryResults() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL), eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .signedCredential("signed-jwt")
                        .credentialOfferUri("openid-credential-offer://x")
                        .deliveryResults(List.of(
                                DeliveryResult.delivered("direct"),
                                DeliveryResult.dispatched("email"),
                                DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("direct")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body.signed_credential").isEqualTo("signed-jwt")
                .jsonPath("$.responses[1].channel").isEqualTo("email")
                .jsonPath("$.responses[1].status").isEqualTo(200)
                .jsonPath("$.responses[1].body").doesNotExist()
                .jsonPath("$.responses[2].channel").isEqualTo("ui")
                .jsonPath("$.responses[2].status").isEqualTo(200)
                .jsonPath("$.responses[2].body.credential_offer_uri").isEqualTo("openid-credential-offer://x");
    }

    /** D-5 retires the 202 wallet-only status: a fully successful request is always 200. */
    @Test
    void createIssuance_WalletOnly_Returns200WithDeliveryResultsBody() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fabc";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL), eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .deliveryResults(List.of(
                                DeliveryResult.dispatched("email"),
                                DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("email")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body").doesNotExist()
                .jsonPath("$.responses[1].channel").isEqualTo("ui")
                .jsonPath("$.responses[1].status").isEqualTo(200)
                .jsonPath("$.responses[1].body.credential_offer_uri").isEqualTo(credentialOfferUri)
                .jsonPath("$.responses[1].body.signed_credential").doesNotExist();
    }

    /**
     * TD-06 (code-review): the {@code delivery} field is rejected at Bean Validation, before
     * {@code IssuanceWorkflow} ever runs -- the request never even reaches the mocked workflow, unlike
     * {@link #createIssuance_InvalidDeliveryMode_Returns400()} below, which mocks a rejection that
     * happens one layer further in ({@code DeliveryMode.parse}, inside the workflow).
     */
    @Test
    void createIssuance_DeliveryContainsControlCharacters_Returns400WithoutInvokingWorkflow() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery("direct\r\nX-Forged-Header: 1")
                .build();

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();

        org.mockito.Mockito.verifyNoInteractions(issuanceWorkflow);
    }

    /**
     * TDG-16: {@code email} only had {@code @NotBlank} before this fix -- a syntactically invalid
     * address reached the delivery workflow unrejected. Now bound by Bean Validation before the
     * workflow ever runs, same pattern as {@link #createIssuance_DeliveryContainsControlCharacters_Returns400WithoutInvokingWorkflow()}.
     */
    @Test
    void createIssuance_MalformedEmail_Returns400WithoutInvokingWorkflow() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("not-an-email")
                .delivery("email")
                .build();

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();

        org.mockito.Mockito.verifyNoInteractions(issuanceWorkflow);
    }

    @Test
    void createIssuance_CredentialConfigurationIdContainsControlCharacters_Returns400WithoutInvokingWorkflow() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema\r\nX-Forged-Header: 1")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery("email")
                .build();

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();

        org.mockito.Mockito.verifyNoInteractions(issuanceWorkflow);
    }

    @Test
    void createIssuance_GrantTypeContainsControlCharacters_Returns400WithoutInvokingWorkflow() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery("email")
                .grantType("authorization_code\r\nX-Forged-Header: 1")
                .build();

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();

        org.mockito.Mockito.verifyNoInteractions(issuanceWorkflow);
    }

    @Test
    void createIssuance_InvalidDeliveryMode_Returns400() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String detail = "Unknown delivery mode: foo";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN), any(), any()))
                .thenReturn(Mono.error(new InvalidDeliveryModeException(detail)));
        when(errorResponseFactory.handleWith(any(), any(), eq("invalid_request"), eq("Invalid request"),
                eq(HttpStatus.BAD_REQUEST), anyString()))
                .thenReturn(Mono.just(new GlobalErrorMessage(
                        "invalid_request", "Invalid request", HttpStatus.BAD_REQUEST.value(), detail,
                        UUID.randomUUID().toString())));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.type").isEqualTo("invalid_request");
    }

    @Test
    void createIssuance_ModeNotEligible_Returns409() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String detail = "Delivery mode 'direct' is not eligible for credential type: test-schema";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN), any(), any()))
                .thenReturn(Mono.error(new DeliveryModeNotEligibleException(detail)));
        when(errorResponseFactory.handleWith(any(), any(), eq("delivery_mode_not_eligible"),
                eq("Delivery mode not eligible"), eq(HttpStatus.CONFLICT), anyString()))
                .thenReturn(Mono.just(new GlobalErrorMessage(
                        "delivery_mode_not_eligible", "Delivery mode not eligible", HttpStatus.CONFLICT.value(),
                        detail, UUID.randomUUID().toString())));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT)
                .expectBody()
                .jsonPath("$.type").isEqualTo("delivery_mode_not_eligible");
    }

    @Test
    void createIssuance_WhenSignedCredentialAndCredentialOfferUriAreAbsent_Returns202AcceptedWithoutBody() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL), eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody().isEmpty();
    }

    @Test
    void createIssuance_WithIdToken_PassesIdTokenToWorkflow() throws JsonProcessingException {
        String idToken = "id-token-value";
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(urlResolver.publicWalletBaseUrl(any())).thenReturn(PUBLIC_WALLET_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(idToken), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL), eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .header("X-Id-Token", idToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody().isEmpty();
    }

    @Test
    void getAllIssuances_ReturnsIssuanceList() {
        String orgId = "testOrganizationId";
        AuthorizationContext authCtx = new AuthorizationContext(orgId, UserRole.LEAR, false, "multi_org");

        IssuanceSummary summary = IssuanceSummary.builder()
                .issuanceId(UUID.randomUUID())
                .subject("testFullName")
                .status("testStatus")
                .updated(Instant.now())
                .organizationIdentifier(orgId)
                .build();

        IssuanceList issuanceList = IssuanceList.builder()
                .issuances(List.of(new IssuanceList.IssuanceEntry(summary)))
                .build();

        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.getAllIssuancesVisibleFor(authCtx))
                .thenReturn(Mono.just(issuanceList));

        webTestClient
                .get()
                .uri(ISSUANCES_PATH)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.credential_procedures").isArray();
    }

    @Test
    void getIssuance_ReturnsCredentialDetails() {
        String orgId = "testOrganizationId";
        String issuanceId = "test-issuance-id";
        AuthorizationContext authCtx = new AuthorizationContext(orgId, UserRole.LEAR, false, "multi_org");

        CredentialDetails details = CredentialDetails.builder()
                .issuanceId(UUID.randomUUID())
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .lifeCycleStatus("VALID")
                .credential(null)
                .build();

        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(authCtx, issuanceId))
                .thenReturn(Mono.just(details));

        webTestClient
                .get()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.lifeCycleStatus").isEqualTo("VALID");
    }

    @Test
    void updateIssuanceStatus_WithdrawnByTenantAdmin_Returns204() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.WITHDRAWN);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.TENANT_ADMIN, false, "multi_org");

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.withdrawIssuance(issuanceId))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void updateIssuanceStatus_ArchivedByTenantAdmin_Returns204() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.ARCHIVED);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.TENANT_ADMIN, false, "multi_org");

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.archiveIssuance(issuanceId))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void updateIssuanceStatus_Revoked_Returns204() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.REVOKED);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.TENANT_ADMIN, false, "multi_org");

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));
        when(revocationWorkflow.revoke(anyString(), eq("Bearer testToken"), eq(issuanceId), isNull(), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void updateIssuanceStatus_UnsupportedStatus_Returns400() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.VALID);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.TENANT_ADMIN, false, "multi_org");

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void updateIssuanceStatus_WhenReadOnlyContext_Returns403() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.WITHDRAWN);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.LEAR, true, "multi_org");

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isForbidden();
    }

    private IssuanceRequest buildIssuanceRequest() {
        return IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .build();
    }
}