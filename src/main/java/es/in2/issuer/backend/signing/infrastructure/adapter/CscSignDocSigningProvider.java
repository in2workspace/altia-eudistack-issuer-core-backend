package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.service.impl.SigningRecoveryServiceImpl;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningContext;
import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.SigningResult;
import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class CscSignDocSigningProvider implements SigningProvider {

    private final RemoteSignatureService remoteSignatureService;
    private final SigningRecoveryServiceImpl signingRecoveryService;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            SigningRequestValidator.validate(request);

            SigningContext ctx = request.context();

            String token = ctx.token();
            String procedureId = ctx.procedureId();
            String email = ctx.email();

            boolean isIssued = procedureId != null && !procedureId.isBlank();

            log.debug("Signing request received. type={}, issued={}, procedureId={}",
                    request.type(), isIssued, procedureId);

            Mono<SigningResult> signingMono =
                    isIssued
                            ? remoteSignatureService.signIssuedCredential(request, token, procedureId, email)
                            : remoteSignatureService.signSystemCredential(request, token);

            Mono<SigningResult> resultMono = signingMono
                    .map(signingResult -> new SigningResult(signingResult.type(), signingResult.data()));

            if (isIssued) {
                resultMono = resultMono.onErrorResume(ex ->
                        signingRecoveryService.handlePostRecoverError(procedureId, email)
                                .onErrorResume(recoveryEx -> {
                                    log.error("Error during post-recovery handling for procedureId={} and email={}", procedureId, email, recoveryEx);
                                    return Mono.empty();
                                })
                                .then(Mono.error(new SigningException("Signing failed via CSC signDoc provider: " + ex.getMessage(), ex)))
                );
            }else {
                resultMono = resultMono.onErrorMap(ex ->
                        new SigningException("Signing failed via CSC signDoc provider: " + ex.getMessage(), ex)
                );
            }
            return resultMono;
        });
    }


}
