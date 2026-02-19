package es.in2.issuer.backend.signing.domain.service;

import reactor.core.publisher.Mono;

import java.util.List;

public interface JwsSignHashService {
    Mono<String> signJwtWithSignHash(String accessToken, String payloadJson, List<String> x5cChainBase64);
}
