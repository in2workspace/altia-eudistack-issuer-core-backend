package es.in2.issuer.backend.signing.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import reactor.core.publisher.Mono;

import java.util.List;

public interface QtspIssuerService {
    Mono<Boolean> validateCredentials();
    Mono<String> requestCertificateInfo(String accessToken, String credentialID);
    Mono<DetailedIssuer> extractIssuerFromCertificateInfo(String certificateInfo);
    boolean isServerMode();
    Mono<DetailedIssuer> resolveRemoteDetailedIssuer();
    Mono<List<String>> extractX5cChain(String certificateInfoJson);
    String getCredentialId();
}
