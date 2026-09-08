package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.oidc4vci.domain.service.PreAuthorizedCodeService;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_CODE_SIZE;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.TX_INPUT_MODE;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_CREDENTIAL_OFFER_PATH;
import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;
import static es.in2.issuer.backend.shared.infrastructure.util.HttpUtils.ensureUrlHasProtocol;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferServiceImpl implements CredentialOfferService {

    private static final String GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    /** Sentinel for "no email failure", so the reactive chain carries a value rather than a null. */
    private static final String NO_EMAIL_ERROR = "";

    private final PreAuthorizedCodeService preAuthorizedCodeService;
    private final TransientStore<String> issuerStateCacheStore;
    private final CredentialOfferCacheRepository credentialOfferCacheRepository;
    private final EmailService emailService;
    private final IssuanceService issuanceService;
    private final TenantConfigService tenantConfigService;

    @Override
    @Observed(name = "oidc4vci.create-and-deliver-credential-offer", contextualName = "create-and-deliver-credential-offer")
    public Mono<CredentialOfferResult> createAndDeliverCredentialOffer(
            String issuanceId, String credentialConfigurationId, String grantType,
            String email, String delivery, String credentialOfferRefreshToken,
            String publicIssuerBaseUrl, String publicWalletBaseUrl) {

        log.info("Delivering credential offer for issuance={} delivery={}", issuanceId, delivery);

        return generateGrant(issuanceId, grantType)
                .flatMap(grantResult -> {
                    CredentialOffer offer = CredentialOffer.builder()
                            .credentialIssuer(publicIssuerBaseUrl)
                            .credentialConfigurationIds(List.of(credentialConfigurationId))
                            .grants(grantResult.grants)
                            .build();

                    CredentialOfferData data = CredentialOfferData.builder()
                            .credentialOffer(offer)
                            .credentialEmail(email)
                            .txCode(grantResult.txCode)
                            .build();

                    return credentialOfferCacheRepository.saveCredentialOffer(data);
                })
                .flatMap(nonce -> buildCredentialOfferUri(publicIssuerBaseUrl, nonce)
                        .flatMap(uri -> deliverOffer(uri, issuanceId, credentialOfferRefreshToken, delivery, publicWalletBaseUrl)));
    }

    private Mono<CredentialOfferResult> deliverOffer(String credentialOfferUri, String issuanceId,
                                                     String credentialOfferRefreshToken, String delivery,
                                                     String publicWalletBaseUrl) {
        Set<DeliveryMode> modes = DeliveryMode.parse(delivery);

        boolean includeUri = modes.stream().anyMatch(mode -> mode.returnsUri);
        boolean sendEmail = modes.contains(DeliveryMode.EMAIL);

        log.info("Delivering credential offer for issuance={} — sendEmail={}, includeUri={}",
                issuanceId, sendEmail, includeUri);

        // The onErrorMap below wraps the whole lookup-and-send chain, not just the send (code-review
        // F3b): findCredentialOfferEmailInfoByIssuanceId can fail too (e.g. a repository error whose
        // message names a table/column/schema -- and the schema name is the tenant), and that failure
        // used to reach describeEmailFailure() raw, bypassing the safe constant below entirely.
        Mono<Void> emailTask = sendEmail
                ? issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId)
                        .flatMap(emailInfo -> buildRefreshUrl(credentialOfferRefreshToken)
                                .flatMap(refreshUrl -> Mono.deferContextual(ctx -> {
                                    String tenantDomain = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
                                    return tenantDomain.contains("kpmg")
                                            ? sendBrandedCredentialOfferEmail(credentialOfferUri, refreshUrl, emailInfo, publicWalletBaseUrl)
                                            : sendLegacyCredentialOfferEmail(credentialOfferUri, refreshUrl, emailInfo, publicWalletBaseUrl);
                                }))
                                .doOnSuccess(v -> log.info("Credential offer email sent for issuanceId={}", issuanceId)))
                        .doOnError(ex -> log.error("Email delivery failed for issuanceId={}: {}",
                                issuanceId, ex.getMessage(), ex))
                        .onErrorMap(ex -> new EmailCommunicationException(MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE))
                : Mono.empty();

        String uri = includeUri ? buildWalletDeepLink(credentialOfferUri, publicWalletBaseUrl) : null;

        // The email failure is reported, not propagated (FR-11): propagating it discarded a URI that
        // was already built, so a bounced email took the QR channel of the same offer down with it.
        return emailTask
                .then(Mono.just(NO_EMAIL_ERROR))
                .onErrorResume(ex -> Mono.just(describeEmailFailure(ex)))
                .map(emailError -> CredentialOfferResult.builder()
                        .credentialOfferUri(uri)
                        .emailError(NO_EMAIL_ERROR.equals(emailError) ? null : emailError)
                        .build());
    }

    private String describeEmailFailure(Throwable ex) {
        String message = ex.getMessage();
        return (message == null || message.isBlank()) ? ex.getClass().getSimpleName() : message;
    }

    private Mono<Void> sendLegacyCredentialOfferEmail(String credentialOfferUri, String refreshUrl,
                                                      CredentialOfferEmailNotificationInfo emailInfo,
                                                      String publicWalletBaseUrl) {
        return emailService.sendCredentialOfferEmail(
                emailInfo.email(),
                CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                buildWalletDeepLink(credentialOfferUri, publicWalletBaseUrl),
                refreshUrl,
                emailInfo.organization(),
                null
        );
    }

    private Mono<Void> sendBrandedCredentialOfferEmail(String credentialOfferUri, String refreshUrl,
                                                       CredentialOfferEmailNotificationInfo emailInfo,
                                                       String publicWalletBaseUrl) {
        return emailService.sendBrandedCredentialOfferEmail(
                emailInfo.email(),
                CREDENTIAL_ACTIVATION_EMAIL_SUBJECT,
                buildWalletDeepLink(credentialOfferUri, publicWalletBaseUrl),
                refreshUrl,
                emailInfo.organization()
        );
    }

    private String buildWalletDeepLink(String credentialOfferUri, String walletUrl) {
        String httpsUrl = credentialOfferUri.startsWith(CREDENTIAL_OFFER_PREFIX)
                ? credentialOfferUri.substring(CREDENTIAL_OFFER_PREFIX.length())
                : URLEncoder.encode(credentialOfferUri, StandardCharsets.UTF_8);

        return walletUrl + WALLET_PROTOCOL_CALLBACK + "?credential_offer_uri=" + httpsUrl;
    }

    private Mono<String> buildRefreshUrl(String credentialOfferRefreshToken) {
        return tenantConfigService.getStringOrThrow("issuer.frontend_url")
                .map(frontendUrl -> frontendUrl + "/credential-offer-refresh/" + credentialOfferRefreshToken);
    }

    private record GrantResult(CredentialOfferGrants grants, String txCode) {}

    private Mono<GrantResult> generateGrant(String issuanceId, String grantType) {
        if (GRANT_TYPE_PRE_AUTHORIZED_CODE.equals(grantType)) {
            return generatePreAuthorizedCodeGrant(issuanceId);
        }
        return generateAuthorizationCodeGrant(issuanceId);
    }

    private Mono<GrantResult> generatePreAuthorizedCodeGrant(String issuanceId) {
        return preAuthorizedCodeService.issuePreAuthorizedCode("issuance", Mono.just(issuanceId))
                .map(preAuthResponse -> {
                    PreAuthorizedCodeGrant preAuthGrant = PreAuthorizedCodeGrant.builder()
                            .preAuthorizedCode(preAuthResponse.preAuthorizedCode())
                            .txCode(TxCode.builder()
                                    .length(TX_CODE_SIZE)
                                    .inputMode(TX_INPUT_MODE)
                                    .description("Enter the activation code")
                                    .build())
                            .build();

                    CredentialOfferGrants grants = CredentialOfferGrants.builder()
                            .preAuthorizedCode(preAuthGrant)
                            .build();

                    return new GrantResult(grants, preAuthResponse.txCodeValue());
                });
    }

    private Mono<GrantResult> generateAuthorizationCodeGrant(String issuanceId) {
        return generateCustomNonce()
                .flatMap(issuerState -> issuerStateCacheStore.add(issuerState, issuanceId)
                        .thenReturn(issuerState))
                .map(issuerState -> {
                    AuthorizationCodeGrant authCodeGrant = AuthorizationCodeGrant.builder()
                            .issuerState(issuerState)
                            .build();

                    CredentialOfferGrants grants = CredentialOfferGrants.builder()
                            .authorizationCode(authCodeGrant)
                            .build();

                    return new GrantResult(grants, null);
                });
    }

    private Mono<String> buildCredentialOfferUri(String baseUrl, String nonce) {
        String rawIssuerOfferUrl = ensureUrlHasProtocol(baseUrl + OID4VCI_CREDENTIAL_OFFER_PATH + "/" + nonce);
        String encodedRawUrl = URLEncoder.encode(rawIssuerOfferUrl, StandardCharsets.UTF_8);

        String finalUri = CREDENTIAL_OFFER_PREFIX + encodedRawUrl;
        log.info("BUILDING URI - Result: {}", finalUri);

        return Mono.just(finalUri);
    }
}