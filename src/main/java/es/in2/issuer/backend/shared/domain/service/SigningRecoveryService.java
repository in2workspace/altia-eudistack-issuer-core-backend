package es.in2.issuer.backend.shared.domain.service;

import reactor.core.publisher.Mono;

public interface SigningRecoveryService {
    Mono<Void> handlePostRecoverError(String procedureId, String email);
}
