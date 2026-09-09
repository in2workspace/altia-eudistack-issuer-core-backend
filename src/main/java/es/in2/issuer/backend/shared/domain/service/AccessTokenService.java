package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import reactor.core.publisher.Mono;

public interface AccessTokenService {
    Mono<String> getCleanBearerToken(String authorizationHeader);
    Mono<String> getOrganizationId(String authorizationHeader);
    Mono<AuthorizationContext> getAuthorizationContext(String authorizationHeader);
    Mono<String> getOrganizationIdFromCurrentSession();
    Mono<AccessTokenContext> resolveAccessTokenContext(String authorizationHeader);

    /**
     * Extracts the {@code tenant} claim from the access token, if present. Empty (not an
     * error) when the claim is absent -- callers that require it decide how to react
     * (security review, EUD-169: {@code CredentialCatalogController} rejects on mismatch).
     */
    Mono<String> getTokenTenant(String authorizationHeader);
}
