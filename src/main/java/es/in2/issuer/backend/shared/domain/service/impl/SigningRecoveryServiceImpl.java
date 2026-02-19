package es.in2.issuer.backend.shared.domain.service.impl;

import java.util.*;
import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.SigningRecoveryService;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import es.in2.issuer.backend.shared.infrastructure.repository.DeferredCredentialMetadataRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;


import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class SigningRecoveryServiceImpl implements SigningRecoveryService {

    private final CredentialProcedureRepository credentialProcedureRepository;
    private final DeferredCredentialMetadataRepository deferredCredentialMetadataRepository;
    private final AppConfig appConfig;
    private final EmailService emailService;

    @Override
    public Mono<Void> handlePostRecoverError(String procedureId, String email) {
        log.info("handlePostRecoverError procedureId={} email={}", procedureId, email);

        UUID id = UUID.fromString(procedureId);
        String domain = appConfig.getIssuerFrontendUrl();

        Mono<CredentialProcedure> cachedProc = credentialProcedureRepository
                .findByProcedureId(id)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("No CredentialProcedure for " + procedureId)))
                .cache();

        Mono<Void> updateOperationMode = cachedProc
                .flatMap(cp -> {
                    cp.setOperationMode(ASYNC);
                    cp.setCredentialStatus(CredentialStatusEnum.PEND_SIGNATURE);
                    return credentialProcedureRepository.save(cp)
                            .doOnSuccess(saved -> log.info("Updated operationMode to Async - Procedure"))
                            .then();
                });

        Mono<Void> updateDeferredMetadata = deferredCredentialMetadataRepository.findByProcedureId(id)
                .switchIfEmpty(Mono.fromRunnable(() ->
                        log.error("No deferred metadata found for procedureId: {}", procedureId)
                ).then(Mono.empty()))
                .flatMap(deferred -> {
                    deferred.setOperationMode(ASYNC);
                    return deferredCredentialMetadataRepository.save(deferred)
                            .doOnSuccess(saved -> log.info("Updated operationMode to Async - Deferred"))
                            .then();
                });

        Mono<Void> sendEmail = cachedProc.flatMap(cp -> {
            String org = cp.getOrganizationIdentifier();
            String updatedBy = cp.getUpdatedBy();
            log.debug("updatedBy in procedure: {}", updatedBy);

            String targetEmail = (email != null && !email.isBlank()) ? email : updatedBy;
            log.info("Preparing email for org {} (to {})", org, targetEmail);

            return emailService.sendPendingSignatureCredentialNotification(
                    targetEmail,
                    "email.pending-credential-notification",
                    procedureId,
                    domain
            );
        });

        return updateOperationMode
                .then(updateDeferredMetadata)
                .then(sendEmail);
    }

}