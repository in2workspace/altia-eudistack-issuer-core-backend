package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.entities.DeferredCredentialMetadata;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import es.in2.issuer.backend.shared.infrastructure.repository.DeferredCredentialMetadataRepository;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.ASYNC;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SigningRecoveryServiceImplTest {

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;
    @Mock
    private DeferredCredentialMetadataRepository deferredCredentialMetadataRepository;
    @Mock
    private AppConfig appConfig;
    @Mock
    private EmailService emailService;
    @InjectMocks
    private SigningRecoveryServiceImpl signingRecoveryService;

    private final String procedureId = UUID.randomUUID().toString();
    private final String email = "user@example.com";
    private final String domain = "https://frontend";
    private CredentialProcedure procedure;

    @BeforeEach
    void setup() {
        procedure = new CredentialProcedure();
        procedure.setProcedureId(UUID.fromString(procedureId));
        procedure.setOrganizationIdentifier("ORG");
        procedure.setUpdatedBy("updated@example.com");
        procedure.setOperationMode("SYNC");
        procedure.setCredentialStatus(CredentialStatusEnum.PEND_SIGNATURE);
    }

    @Test
    void handlePostRecoverError_updatesEntitiesAndSendsEmail() {
        when(credentialProcedureRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.just(procedure));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        when(deferredCredentialMetadataRepository.findByProcedureId(any(UUID.class)))
                .thenReturn(Mono.empty());

        when(appConfig.getIssuerFrontendUrl()).thenReturn(domain);
        when(emailService.sendPendingSignatureCredentialNotification(any(), any(), any(), any()))
                .thenReturn(Mono.empty());

        StepVerifier.create(signingRecoveryService.handlePostRecoverError(procedureId, email))
                .verifyComplete();

        assertThat(procedure.getOperationMode()).isEqualTo(ASYNC);

        assertThat(procedure.getCredentialStatus()).isEqualTo(CredentialStatusEnum.PEND_SIGNATURE);

        verify(emailService).sendPendingSignatureCredentialNotification(
                eq(email),
                eq("email.pending-credential-notification"),
                eq(procedureId),
                eq(domain)
        );
    }

    @Test
    void handlePostRecoverError_usesUpdatedByWhenEmailIsNullOrBlank() {
        when(credentialProcedureRepository.findByProcedureId(any(UUID.class))).thenReturn(Mono.just(procedure));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class))).thenReturn(Mono.just(procedure));
        when(deferredCredentialMetadataRepository.findByProcedureId(any(UUID.class))).thenReturn(Mono.empty());
        when(appConfig.getIssuerFrontendUrl()).thenReturn(domain);
        when(emailService.sendPendingSignatureCredentialNotification(any(), any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(signingRecoveryService.handlePostRecoverError(procedureId, " "))
                .verifyComplete();
        verify(emailService).sendPendingSignatureCredentialNotification(eq("updated@example.com"), any(), eq(procedureId), eq(domain));
    }

    @Test
    void handlePostRecoverError_noCredentialProcedure_throwsError() {
        when(credentialProcedureRepository.findByProcedureId(any(UUID.class))).thenReturn(Mono.empty());
        StepVerifier.create(signingRecoveryService.handlePostRecoverError(procedureId, email))
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    void handlePostRecoverError_deferredMetadataFound_updatesIt() {
        DeferredCredentialMetadata deferred = mock(DeferredCredentialMetadata.class, RETURNS_DEEP_STUBS);
        when(credentialProcedureRepository.findByProcedureId(any(UUID.class))).thenReturn(Mono.just(procedure));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class))).thenReturn(Mono.just(procedure));
        when(deferredCredentialMetadataRepository.findByProcedureId(any(UUID.class))).thenReturn(Mono.just(deferred));
        when(deferredCredentialMetadataRepository.save(any(DeferredCredentialMetadata.class))).thenReturn(Mono.just(deferred));
        when(appConfig.getIssuerFrontendUrl()).thenReturn(domain);
        when(emailService.sendPendingSignatureCredentialNotification(any(), any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(signingRecoveryService.handlePostRecoverError(procedureId, email))
                .verifyComplete();
        verify(deferredCredentialMetadataRepository).save(deferred);
    }
}