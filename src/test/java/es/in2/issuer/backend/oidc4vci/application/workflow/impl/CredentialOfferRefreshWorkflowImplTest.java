package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.AUTHORIZATION_CODE;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferRefreshWorkflowImplTest {

    private static final String CREDENTIAL_OFFER_REFRESH_TOKEN = "valid-refresh-token";
    private static final String UNKNOWN_CREDENTIAL_OFFER_REFRESH_TOKEN = "unknown-refresh-token";
    private static final String PUBLIC_ISSUER_BASE_URL = "https://test.example/issuer";
    private static final String PUBLIC_WALLET_BASE_URL = "https://test.example/wallet";
    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.4";
    private static final String EMAIL = "test@example.com";

    @Mock
    private IssuanceService issuanceService;

    @Mock
    private CredentialOfferService credentialOfferService;

    @InjectMocks
    private CredentialOfferRefreshWorkflowImpl workflow;

    @Test
    void refreshCredentialOffer_WhenIssuanceIsDraft_ShouldCreateAndDeliverCredentialOffer() {
        UUID issuanceId = UUID.randomUUID();
        Issuance issuance = buildIssuance(issuanceId, CredentialStatusEnum.DRAFT, AUTHORIZATION_CODE);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()),
                eq(CREDENTIAL_TYPE),
                eq(AUTHORIZATION_CODE),
                eq(EMAIL),
                eq(DeliveryMode.EMAIL.value),
                eq(CREDENTIAL_OFFER_REFRESH_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL),
                eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(CredentialOfferResult.builder().build()));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL, PUBLIC_WALLET_BASE_URL))
                .verifyComplete();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                eq(issuanceId.toString()),
                eq(CREDENTIAL_TYPE),
                eq(AUTHORIZATION_CODE),
                eq(EMAIL),
                eq(DeliveryMode.EMAIL.value),
                eq(CREDENTIAL_OFFER_REFRESH_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL),
                eq(PUBLIC_WALLET_BASE_URL));
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsDraft_ShouldReusePersistedPreAuthorizedGrant() {
        UUID issuanceId = UUID.randomUUID();
        String preAuthGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
        Issuance issuance = buildIssuance(issuanceId, CredentialStatusEnum.DRAFT, preAuthGrant);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()),
                eq(CREDENTIAL_TYPE),
                eq(preAuthGrant),
                eq(EMAIL),
                eq(DeliveryMode.EMAIL.value),
                eq(CREDENTIAL_OFFER_REFRESH_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL),
                eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.just(CredentialOfferResult.builder().build()));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL, PUBLIC_WALLET_BASE_URL))
                .verifyComplete();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                eq(issuanceId.toString()),
                eq(CREDENTIAL_TYPE),
                eq(preAuthGrant),
                eq(EMAIL),
                eq(DeliveryMode.EMAIL.value),
                eq(CREDENTIAL_OFFER_REFRESH_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL),
                eq(PUBLIC_WALLET_BASE_URL));
    }

    @Test
    void refreshCredentialOffer_WhenCredentialOfferRefreshTokenIsUnknown_ShouldReturnNotFound() {
        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(UNKNOWN_CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.refreshCredentialOffer(UNKNOWN_CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL, PUBLIC_WALLET_BASE_URL))
                .expectErrorMatches(error -> error instanceof ResponseStatusException responseStatusException
                        && responseStatusException.getStatusCode() == HttpStatus.NOT_FOUND
                        && "Invalid or unknown credential offer refresh token"
                        .equals(responseStatusException.getReason()))
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(UNKNOWN_CREDENTIAL_OFFER_REFRESH_TOKEN);
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsNotDraft_ShouldReturnGone() {
        Issuance issuance = buildIssuance(UUID.randomUUID(), CredentialStatusEnum.VALID, AUTHORIZATION_CODE);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL, PUBLIC_WALLET_BASE_URL))
                .expectErrorMatches(error -> error instanceof ResponseStatusException responseStatusException
                        && responseStatusException.getStatusCode() == HttpStatus.GONE
                        && "This credential offer can no longer be refreshed"
                        .equals(responseStatusException.getReason()))
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsRevoked_ShouldReturnGone() {
        Issuance issuance = buildIssuance(UUID.randomUUID(), CredentialStatusEnum.REVOKED, AUTHORIZATION_CODE);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL, PUBLIC_WALLET_BASE_URL))
                .expectErrorMatches(error -> error instanceof ResponseStatusException responseStatusException
                        && responseStatusException.getStatusCode() == HttpStatus.GONE
                        && "This credential offer can no longer be refreshed"
                        .equals(responseStatusException.getReason()))
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsWithdrawn_ShouldReturnGone() {
        Issuance issuance = buildIssuance(UUID.randomUUID(), CredentialStatusEnum.WITHDRAWN, AUTHORIZATION_CODE);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL, PUBLIC_WALLET_BASE_URL))
                .expectErrorMatches(error -> error instanceof ResponseStatusException responseStatusException
                        && responseStatusException.getStatusCode() == HttpStatus.GONE
                        && "This credential offer can no longer be refreshed"
                        .equals(responseStatusException.getReason()))
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void refreshCredentialOffer_WhenCreateAndDeliverCredentialOfferFails_ShouldPropagateError() {
        UUID issuanceId = UUID.randomUUID();
        Issuance issuance = buildIssuance(issuanceId, CredentialStatusEnum.DRAFT, AUTHORIZATION_CODE);
        RuntimeException expectedException = new RuntimeException("Credential offer delivery failed");

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()),
                eq(CREDENTIAL_TYPE),
                eq(AUTHORIZATION_CODE),
                eq(EMAIL),
                eq(DeliveryMode.EMAIL.value),
                eq(CREDENTIAL_OFFER_REFRESH_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL),
                eq(PUBLIC_WALLET_BASE_URL)))
                .thenReturn(Mono.error(expectedException));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL, PUBLIC_WALLET_BASE_URL))
                .expectErrorMatches(error -> error == expectedException)
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                eq(issuanceId.toString()),
                eq(CREDENTIAL_TYPE),
                eq(AUTHORIZATION_CODE),
                eq(EMAIL),
                eq(DeliveryMode.EMAIL.value),
                eq(CREDENTIAL_OFFER_REFRESH_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL),
                eq(PUBLIC_WALLET_BASE_URL));
    }

    private Issuance buildIssuance(UUID issuanceId, CredentialStatusEnum credentialStatus, String grantType) {
        return Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(credentialStatus)
                .credentialType(CREDENTIAL_TYPE)
                .email(EMAIL)
                .grantType(grantType)
                .build();
    }
}