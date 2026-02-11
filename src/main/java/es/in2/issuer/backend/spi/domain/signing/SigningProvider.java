package es.in2.issuer.backend.spi.domain.signing;

import es.in2.issuer.backend.spi.domain.exception.SigningException;
import es.in2.issuer.backend.spi.domain.model.SigningRequest;
import es.in2.issuer.backend.spi.domain.model.SigningResult;
import reactor.core.publisher.Mono;

public interface SigningProvider {
    Mono<SigningResult> sign(SigningRequest request) throws SigningException;
}
