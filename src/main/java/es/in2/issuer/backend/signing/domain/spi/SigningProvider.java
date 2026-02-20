package es.in2.issuer.backend.signing.domain.spi;

import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import reactor.core.publisher.Mono;

public interface SigningProvider {
    Mono<SigningResult> sign(SigningRequest request);
}
