package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.dto.PreAuthorizedCodeResponse;
import es.in2.issuer.backend.shared.domain.model.dto.TxCode;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialOfferServiceImplTest {

    @Mock
    private PreAuthorizedCodeService preAuthorizedCodeService;
    @Mock
    private TransientStore<String> issuerStateCacheStore;
    @Mock
    private CredentialOfferCacheRepository credentialOfferCacheRepository;
    @Mock
    private EmailService emailService;
    @Mock
    private IssuanceService issuanceService;
    @Mock
    private TenantConfigService tenantConfigService;

    @InjectMocks
    private CredentialOfferServiceImpl credentialOfferService;

    @Test
    void createAndDeliverCredentialOffer_withPreAuthorizedCodeAndUiDelivery_shouldReturnUri() {
        String issuanceId = "test-issuance-id";
        String configId = "learcredential.employee.w3c.4";

        when(preAuthorizedCodeService.issuePreAuthorizedCode(anyString(), any()))
                .thenReturn(Mono.just(PreAuthorizedCodeResponse.builder()
                        .preAuthorizedCode("pre-auth-code-123")
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .txCodeValue("1234")
                        .build()));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, configId, "urn:ietf:params:oauth:grant-type:pre-authorized_code", "test@example.com", "ui", "refresh-token", "https://example.com", "https://example.com/wallet"))
                .assertNext(result -> {
                    assertThat(result.credentialOfferUri()).startsWith("https://example.com/wallet/protocol/callback");
                    assertThat(result.credentialOfferUri()).contains("credential_offer_uri=");
                })
                .verifyComplete();
    }

    @Test
    void createAndDeliverCredentialOffer_withAuthorizationCodeAndUiDelivery_shouldReturnUri() {
        String issuanceId = "test-issuance-id";
        String configId = "learcredential.employee.w3c.4";

        when(issuerStateCacheStore.add(anyString(), eq(issuanceId)))
                .thenReturn(Mono.just("cached"));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, configId, "authorization_code", "test@example.com", "ui", "refresh-token", "https://example.com", "https://example.com/wallet"))
                .assertNext(result -> {
                    assertThat(result.credentialOfferUri()).startsWith("https://example.com/wallet/protocol/callback");
                    assertThat(result.credentialOfferUri()).contains("credential_offer_uri=");
                })
                .verifyComplete();
    }

    @Test
    void createAndDeliverCredentialOffer_withAuthorizationCodeAndEmailDelivery_shouldSendEmailWithoutTxCode() {
        String issuanceId = "test-issuance-id";
        String configId = "learcredential.employee.w3c.4";

        when(tenantConfigService.getStringOrThrow("issuer.frontend_url"))
                .thenReturn(Mono.just("https://frontend.example.com/issuer"));
        when(issuerStateCacheStore.add(anyString(), eq(issuanceId)))
                .thenReturn(Mono.just("cached"));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "TestOrg")));
        when(emailService.sendCredentialOfferEmail(
                anyString(), anyString(), anyString(), anyString(), anyString(), isNull()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, configId, "authorization_code", "test@example.com", "email", "refresh-token", "https://example.com", "https://example.com/wallet"))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isNull())
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(
                eq("test@example.com"), anyString(), anyString(), anyString(), eq("TestOrg"), isNull());
    }

    /**
     * Code-review F3b. The onErrorMap that turns any email-leg failure into the safe
     * EmailCommunicationException constant used to wrap only the send step; a failure in the
     * repository lookup that precedes it (findCredentialOfferEmailInfoByIssuanceId) reached
     * describeEmailFailure raw. An R2DBC failure names table/column/schema, and the schema name is
     * the tenant.
     */
    @Test
    void createAndDeliverCredentialOffer_whenEmailInfoLookupFails_reportsTheSafeConstantNotTheRawMessage() {
        String issuanceId = "test-issuance-id";
        String configId = "learcredential.employee.w3c.4";

        when(issuerStateCacheStore.add(anyString(), eq(issuanceId)))
                .thenReturn(Mono.just("cached"));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId))
                .thenReturn(Mono.error(new RuntimeException(
                        "relation \"tenant_acme.issuance\" violates foreign key constraint")));

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, configId, "authorization_code", "test@example.com", "email", "refresh-token", "https://example.com", "https://example.com/wallet"))
                .assertNext(result -> {
                    assertThat(result.emailError()).isEqualTo("Error during communication with the mail server");
                    assertThat(result.emailError()).doesNotContain("tenant_acme");
                })
                .verifyComplete();

        verifyNoInteractions(emailService);
    }

    @Test
    void createAndDeliverCredentialOffer_withPreAuthorizedCodeAndEmailDelivery_shouldSendEmailWithoutTxCode() {
        String issuanceId = "test-issuance-id";
        String configId = "learcredential.employee.w3c.4";

        when(tenantConfigService.getStringOrThrow("issuer.frontend_url"))
                .thenReturn(Mono.just("https://frontend.example.com/issuer"));
        when(preAuthorizedCodeService.issuePreAuthorizedCode(anyString(), any()))
                .thenReturn(Mono.just(PreAuthorizedCodeResponse.builder()
                        .preAuthorizedCode("pre-auth-code-123")
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .txCodeValue("1234")
                        .build()));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "TestOrg")));
        when(emailService.sendCredentialOfferEmail(
                anyString(), anyString(), anyString(), anyString(), anyString(), isNull()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        issuanceId, configId, "urn:ietf:params:oauth:grant-type:pre-authorized_code", "test@example.com", "email", "refresh-token", "https://example.com", "https://example.com/wallet"))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isNull())
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(
                eq("test@example.com"), anyString(), anyString(), anyString(), eq("TestOrg"), isNull());
    }

    @Test
    void createAndDeliverCredentialOffer_withKpmgTenantAndEmailDelivery_callsSendBrandedEmail() {
        // Arrange
        when(tenantConfigService.getStringOrThrow("issuer.frontend_url"))
                .thenReturn(Mono.just("https://kpmg.eudistack.net/issuer"));
        when(preAuthorizedCodeService.issuePreAuthorizedCode(anyString(), any()))
                .thenReturn(Mono.just(PreAuthorizedCodeResponse.builder()
                        .preAuthorizedCode("pre-auth-code")
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .txCodeValue("123456").build()));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("nonce"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId("issuance-kpmg"))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("user@kpmg.com", "KPMG")));
        when(emailService.sendBrandedCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "issuance-kpmg", "learcredential.employee.sd.1",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        "user@kpmg.com", "email", "refresh-token", "https://kpmg.eudistack.net/issuer", "https://kpmg.eudistack.net/wallet")
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "kpmg")))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isNull())
                .verifyComplete();

        verify(emailService).sendBrandedCredentialOfferEmail(
                eq("user@kpmg.com"), anyString(), argThat(url -> url.startsWith("https://kpmg.eudistack.net/wallet")), anyString(), eq("KPMG"));
        verify(emailService, never()).sendCredentialOfferEmail(any(), any(), any(), any(), any(), any());
    }

    @Test
    void createAndDeliverCredentialOffer_withNonKpmgTenantAndEmailDelivery_callsSendLegacyEmail() {
        // Arrange
        when(tenantConfigService.getStringOrThrow("issuer.frontend_url"))
                .thenReturn(Mono.just("https://sandbox.eudistack.net/issuer"));
        when(preAuthorizedCodeService.issuePreAuthorizedCode(anyString(), any()))
                .thenReturn(Mono.just(PreAuthorizedCodeResponse.builder()
                        .preAuthorizedCode("pre-auth-code")
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .txCodeValue("123456").build()));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("nonce"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId("issuance-sandbox"))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("user@sandbox.com", "Sandbox Org")));
        when(emailService.sendCredentialOfferEmail(any(), any(), any(), any(), any(), isNull()))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(credentialOfferService.createAndDeliverCredentialOffer(
                        "issuance-sandbox", "learcredential.employee.sd.1",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        "user@sandbox.com", "email", "refresh-token", "https://sandbox.eudistack.net/issuer", "https://sandbox.eudistack.net/wallet")
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "sandbox")))
                .assertNext(result -> assertThat(result.credentialOfferUri()).isNull())
                .verifyComplete();

        verify(emailService).sendCredentialOfferEmail(
                eq("user@sandbox.com"), any(), argThat(url -> url.startsWith("https://sandbox.eudistack.net/wallet")), any(), eq("Sandbox Org"), isNull());
        verify(emailService, never()).sendBrandedCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), anyString());
    }
}
