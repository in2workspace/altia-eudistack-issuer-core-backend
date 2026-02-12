package es.in2.issuer.backend.spi.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.model.dto.SignatureConfiguration;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.spi.domain.exception.SigningException;
import es.in2.issuer.backend.spi.domain.model.SigningContext;
import es.in2.issuer.backend.spi.domain.model.SigningRequest;
import es.in2.issuer.backend.spi.domain.model.SigningResult;
import es.in2.issuer.backend.spi.domain.model.SigningType;
import es.in2.issuer.backend.spi.domain.signing.SigningProvider;
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

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            try {
                validate(request);

                SignatureRequest legacyRequest = toLegacy(request);

                SigningContext ctx = request.context();
                String token = ctx.token();
                String procedureId = ctx.procedureId();
                String email = ctx.email();

                log.debug("Signing request received. type={}, procedureId={}", request.type(), request.context().procedureId());

                return remoteSignatureService
                        .signIssuedCredential(legacyRequest, token, procedureId != null ? procedureId : "", email)
                        .map(signedData -> new SigningResult(mapSigningType(signedData.type()), signedData.data()))
                        .onErrorMap(ex -> {
                            log.error("CSC signDoc provider failed. type={}, procedureId={}, reason={}",
                                    request.type(), procedureId, ex.getMessage(), ex);
                            return new SigningException("Signing failed via CSC signDoc provider: " + ex.getMessage(), ex);
                        });
            } catch (SigningException ex) {
                return Mono.error(ex);
            }
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


    private void validate(SigningRequest request) {
        if (request == null) {
            throw new SigningException("SigningRequest must not be null");
        }
        if (request.type() == null) {
            throw new SigningException("SigningRequest.type must not be null");
        }
        if (request.data() == null || request.data().isBlank()) {
            throw new SigningException("SigningRequest.data must not be null/blank");
        }
        if (request.context() == null) {
            throw new SigningException("SigningRequest.context must not be null");
        }
        if (request.context().token() == null || request.context().token().isBlank()) {
            throw new SigningException("SigningContext.token must not be null/blank");
        }
    }

    private SignatureType mapType(SigningType type) {
        return switch (type) {
            case JADES -> SignatureType.JADES;
            case COSE -> SignatureType.COSE;
        };
    }
}
