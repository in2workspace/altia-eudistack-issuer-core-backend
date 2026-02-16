package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.model.dto.SignatureConfiguration;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.impl.SigningRecoveryServiceImpl;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningContext;
import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Collections;

/**
 * PR1 implementation: "signDoc strategy" provider.
 * NOTE: In PR1 this is a wrapper around the existing RemoteSignatureService implementation.
 */

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

            SignatureRequest legacyRequest = toLegacy(request);
            SigningContext ctx = request.context();

            String token = ctx.token();
            String procedureId = ctx.procedureId();
            String email = ctx.email();

            boolean isIssued = procedureId != null && !procedureId.isBlank();

            log.debug("Signing request received. type={}, issued={}, procedureId={}",
                    request.type(), isIssued, procedureId);

            Mono<es.in2.issuer.backend.shared.domain.model.dto.SignedData> signingMono =
                    isIssued
                            ? remoteSignatureService.signIssuedCredential(legacyRequest, token, procedureId, email)
                            : remoteSignatureService.signSystemCredential(legacyRequest, token);

            Mono<SigningResult> resultMono = signingMono
                    .map(signedData -> new SigningResult(mapSigningType(signedData.type()), signedData.data()));

            if (isIssued) {
                resultMono = resultMono.onErrorResume(ex ->
                        signingRecoveryService.handlePostRecoverError(procedureId, email)
                                .then(Mono.error(ex))
                );
            }

            return resultMono.onErrorMap(ex ->
                    new SigningException("Signing failed via CSC signDoc provider: " + ex.getMessage(), ex)
            );
        });
    }

    private SigningType mapSigningType(SignatureType type) {
        return switch (type) {
            case JADES -> SigningType.JADES;
            case COSE -> SigningType.COSE;
        };
    }

    private SignatureRequest toLegacy(SigningRequest request) {
        SignatureType legacyType = mapType(request.type());
        return new SignatureRequest(
                new SignatureConfiguration(legacyType, Collections.emptyMap()),
                request.data()
        );
    }

    private SignatureType mapType(SigningType type) {
        return switch (type) {
            case JADES -> SignatureType.JADES;
            case COSE -> SignatureType.COSE;
        };
    }
}
