package es.in2.issuer.backend.signing.domain.service;

import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import reactor.core.publisher.Mono;

public interface RemoteSignatureService {
    Mono<SigningResult> signIssuedCredential(SigningRequest signingRequest, String token, String procedureId, String email);
    Mono<SigningResult> signSystemCredential(SigningRequest signingRequest, String token);
}
