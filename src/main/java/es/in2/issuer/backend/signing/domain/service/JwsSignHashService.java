package es.in2.issuer.backend.signing.domain.service;

import reactor.core.publisher.Mono;

public interface JwsSignHashService {
    Mono<String> signJwtWithSignHash(String accessToken, String headerJson, String payloadJson);
}
