package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import com.nimbusds.jose.Payload;
import es.in2.issuer.backend.apiclient.domain.exception.ApiClientAuthenticationException;
import es.in2.issuer.backend.apiclient.domain.model.AuthenticatedApiClient;
import es.in2.issuer.backend.apiclient.domain.service.ApiClientAuthenticationService;
import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.ClientAttestationHeaders;
import es.in2.issuer.backend.shared.domain.service.ClientAttestationValidationService;
import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationCodeData;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceIdAndRefreshToken;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceIdAndTxCode;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.PkceVerifier;
import es.in2.issuer.backend.shared.domain.service.RefreshTokenService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.ACCESS_TOKEN_EXPIRATION_MINUTES;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.AUTHORIZATION_CODE_GRANT_TYPE;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.CLIENT_CREDENTIALS_GRANT_TYPE;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.M2M_ACCESS_TOKEN_EXPIRATION_MINUTES;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.M2M_CALLER_TYPE;
import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.M2M_INTAKE_SCOPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private static final String TOKEN_TYPE_BEARER = "bearer";
    private static final String ATTEST_JWT_CLIENT_AUTH = "attest_jwt_client_auth";
    private static final String TOKEN_TYPE_DPOP = "DPoP";

    private final TransientStore<IssuanceIdAndTxCode> txCodeCacheStore;
    private final TransientStore<IssuanceIdAndRefreshToken> refreshTokenCacheStore;
    private final TransientStore<AuthorizationCodeData> authorizationCodeCacheStore;
    private final JWTService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final IssuanceService issuanceService;
    private final PkceVerifier pkceVerifier;
    private final DpopValidationService dpopValidationService;
    private final Oid4vciProfilePort profileProperties;
    private final IssuanceMetrics issuanceMetrics;
    private final TransientStore<String> issuerStateCacheStore;
    private final ApiClientAuthenticationService apiClientAuthenticationService;
    private final ClientAttestationValidationService clientAttestationValidationService;

    @Override
    @Observed(name = "oid4vci.token", contextualName = "oid4vci-handle-token")
    public Mono<TokenResponse> exchangeToken(TokenRequest request, String dpopHeader,
                                             ClientAttestationHeaders clientAttestation,
                                             String tokenEndpointUri, String publicIssuerBaseUrl) {
        String grantType = request.grantType();

        Mono<TokenResponse> flow;
        if (GRANT_TYPE.equals(grantType)) {
            flow = handlePreAuthorizedCode(publicIssuerBaseUrl, request.preAuthorizedCode(), request.txCode());
        } else if (REFRESH_TOKEN_GRANT_TYPE.equals(grantType)) {
            flow = handleRefreshToken(publicIssuerBaseUrl, request.refreshToken());
        } else if (AUTHORIZATION_CODE_GRANT_TYPE.equals(grantType)) {
            flow = Mono.defer(() -> {
                final String attestedClientId;
                try {
                    attestedClientId = authenticateClient(clientAttestation, publicIssuerBaseUrl);
                } catch (IllegalArgumentException e) {
                    log.warn("Client attestation rejected at the token endpoint: {}", e.getMessage());
                    return Mono.error(OAuthTokenException.invalidClient());
                }
                return handleAuthorizationCode(publicIssuerBaseUrl, request.code(), request.redirectUri(),
                        request.codeVerifier(), dpopHeader, tokenEndpointUri, attestedClientId);
            });
        } else if (CLIENT_CREDENTIALS_GRANT_TYPE.equals(grantType)) {
            flow = handleClientCredentials(publicIssuerBaseUrl, request.clientId(), request.clientSecret());
        } else {
            return Mono.error(OAuthTokenException.unsupportedGrantType(grantType));
        }

        String grantTag = resolveGrantTag(grantType);
        return flow
                .doOnSuccess(r -> issuanceMetrics.recordTokenRequest(grantTag, "success"))
                .doOnError(e -> issuanceMetrics.recordTokenRequest(grantTag, "error"));
    }

    private String resolveGrantTag(String grantType) {
        if (GRANT_TYPE.equals(grantType)) return PRE_AUTHORIZED_CODE;
        if (REFRESH_TOKEN_GRANT_TYPE.equals(grantType)) return REFRESH_TOKEN_GRANT_TYPE;
        if (AUTHORIZATION_CODE_GRANT_TYPE.equals(grantType)) return AUTHORIZATION_CODE;
        if (CLIENT_CREDENTIALS_GRANT_TYPE.equals(grantType)) return CLIENT_CREDENTIALS_GRANT_TYPE;
        return "unknown";
    }

    // -- Client Credentials Flow (EUD-75, US-02: M2M intake authentication) --

    private Mono<TokenResponse> handleClientCredentials(String baseUrl, String clientId, String clientSecret) {
        log.debug("Token request: grant_type=client_credentials");
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
            return apiClientAuthenticationService.authenticateForToken(tenant, clientId, clientSecret)
                    .map(client -> buildM2mTokenResponse(baseUrl, client))
                    .onErrorMap(ApiClientAuthenticationException.class, ex -> OAuthTokenException.invalidClient());
        });
    }

    private TokenResponse buildM2mTokenResponse(String baseUrl, AuthenticatedApiClient client) {
        Instant issueTime = Instant.now();
        long accessTokenExp = issueTime.plus(M2M_ACCESS_TOKEN_EXPIRATION_MINUTES, ChronoUnit.MINUTES).getEpochSecond();

        // can_trigger_issuance is embedded here (not re-queried from api_client
        // downstream) so the intake gate can authorize from JWT claims alone —
        // re-resolving the ApiClient per intake request would both duplicate
        // the token endpoint's DB round-trip and blow the p95 filter overhead
        // budget (NFR-S-EUD75-01).
        Payload payload = new Payload(Map.of(
                "iss", baseUrl,
                "sub", client.clientId(),
                "client_id", client.clientId(),
                "caller_type", M2M_CALLER_TYPE,
                "scope", M2M_INTAKE_SCOPE,
                "can_trigger_issuance", client.canTriggerIssuance(),
                "iat", issueTime.getEpochSecond(),
                "exp", accessTokenExp,
                "jti", UUID.randomUUID().toString()
        ));
        String accessToken = jwtService.issueJWT(payload.toString());

        return TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType(TOKEN_TYPE_BEARER)
                .expiresIn(accessTokenExp - Instant.now().getEpochSecond())
                .refreshToken(null)
                .build();
    }

    // -- Pre-Authorized Code Flow --

    private Mono<TokenResponse> handlePreAuthorizedCode(String baseUrl, String preAuthorizedCode, String txCode) {
        log.debug("Token request: grant_type=pre-authorized_code");
        return validatePreAuthorizedCodeAndTxCode(preAuthorizedCode, txCode)
                .then(Mono.defer(() -> buildTokenResponse(baseUrl, preAuthorizedCode)));
    }

    private Mono<Void> validatePreAuthorizedCodeAndTxCode(String preAuthorizedCode, String txCode) {
        return txCodeCacheStore
                .get(preAuthorizedCode)
                .switchIfEmpty(Mono.error(OAuthTokenException.invalidGrant("Invalid pre-authorized code")))
                .flatMap(data -> {
                    if (data.TxCode().equals(txCode)) {
                        return Mono.empty();
                    }
                    log.warn("Invalid tx_code for pre-authorized code");
                    return Mono.error(OAuthTokenException.invalidGrant("Invalid tx code"));
                });
    }

    private Mono<TokenResponse> buildTokenResponse(String baseUrl, String preAuthorizedCode) {
        Instant issueTime = Instant.now();
        long accessTokenExp = computeAccessTokenExpiration(issueTime);
        long refreshTokenExp = refreshTokenService.computeRefreshTokenExpirationTime(issueTime);
        String refreshToken = refreshTokenService.issueRefreshToken();

        return txCodeCacheStore.get(preAuthorizedCode)
                .map(IssuanceIdAndTxCode::issuanceId)
                .flatMap(issuanceId -> {
                    String accessToken = buildAccessToken(baseUrl, issuanceId, issueTime.getEpochSecond(), accessTokenExp);
                    return storeRefreshToken(issuanceId, preAuthorizedCode, refreshToken, refreshTokenExp)
                            .thenReturn(TokenResponse.builder()
                                    .accessToken(accessToken)
                                    .tokenType(TOKEN_TYPE_BEARER)
                                    .expiresIn(accessTokenExp - Instant.now().getEpochSecond())
                                    .refreshToken(refreshToken)
                                    .build());
                });
    }

    private String buildAccessToken(String baseUrl, String issuanceId, long iat, long exp) {
        Payload payload = new Payload(Map.of(
                "iss", baseUrl,
                "aud", baseUrl,
                "iat", iat,
                "exp", exp,
                "jti", UUID.randomUUID().toString(),
                "pid", issuanceId
        ));
        return jwtService.issueJWT(payload.toString());
    }

    // -- Refresh Token Flow --

    private Mono<TokenResponse> handleRefreshToken(String baseUrl, String refreshToken) {
        log.debug("Token request: grant_type=refresh_token");
        return refreshTokenCacheStore
                .get(refreshToken)
                .switchIfEmpty(Mono.error(OAuthTokenException.invalidGrant("Invalid refresh token")))
                .flatMap(data -> validateRefreshTokenData(data, refreshToken)
                        .then(refreshTokenCacheStore.delete(refreshToken))
                        .then(Mono.defer(() -> buildRefreshedTokenResponse(baseUrl, data.issuanceId()))));
    }

    private Mono<Void> validateRefreshTokenData(IssuanceIdAndRefreshToken data, String refreshToken) {
        return issuanceService
                .getCredentialStatusByIssuanceId(data.issuanceId())
                .map(CredentialStatusEnum::valueOf)
                .flatMap(status -> {
                    if (CredentialStatusEnum.VALID.equals(status)) {
                        return Mono.error(OAuthTokenException.invalidGrant(
                                "Cannot refresh token: the associated credential is already valid"));
                    }
                    if (!data.refreshTokenJti().equals(refreshToken)) {
                        return Mono.error(OAuthTokenException.invalidGrant("Invalid refresh token"));
                    }
                    if (Instant.now().getEpochSecond() >= data.refreshTokenExpiresAt()) {
                        return Mono.error(OAuthTokenException.invalidGrant("Refresh token expired"));
                    }
                    return Mono.empty();
                });
    }

    private Mono<TokenResponse> buildRefreshedTokenResponse(String baseUrl, String issuanceId) {
        Instant issueTime = Instant.now();
        long accessTokenExp = computeAccessTokenExpiration(issueTime);
        long refreshTokenExp = refreshTokenService.computeRefreshTokenExpirationTime(issueTime);
        String newRefreshToken = refreshTokenService.issueRefreshToken();
        String accessToken = buildAccessToken(baseUrl, issuanceId, issueTime.getEpochSecond(), accessTokenExp);

        return storeRefreshToken(issuanceId, null, newRefreshToken, refreshTokenExp)
                .thenReturn(TokenResponse.builder()
                        .accessToken(accessToken)
                        .tokenType(TOKEN_TYPE_BEARER)
                        .expiresIn(accessTokenExp - Instant.now().getEpochSecond())
                        .refreshToken(newRefreshToken)
                        .build());
    }

    // -- Authorization Code Flow --

    /**
     * Authenticates the client with attestation-based client authentication and returns the
     * attested client_id, or null when the active profile does not use that method. The token
     * endpoint has to authenticate the client in its own right: PAR having validated the
     * attestation says nothing about who is presenting the code minutes later.
     */
    private String authenticateClient(ClientAttestationHeaders clientAttestation, String publicIssuerBaseUrl) {
        if (!ATTEST_JWT_CLIENT_AUTH.equals(profileProperties.authorizationCode().clientAuthMethod())) {
            return null;
        }
        String attestation = clientAttestation != null ? clientAttestation.attestation() : null;
        String pop = clientAttestation != null ? clientAttestation.pop() : null;
        return clientAttestationValidationService.validateHeaders(attestation, pop, publicIssuerBaseUrl);
    }

    private Mono<TokenResponse> handleAuthorizationCode(
            String baseUrl, String code, String redirectUri, String codeVerifier, String dpopHeader,
            String tokenEndpointUri, String attestedClientId
    ) {
        log.debug("Token request: grant_type=authorization_code");
        return authorizationCodeCacheStore.get(code)
                .switchIfEmpty(Mono.error(OAuthTokenException.invalidGrant("Invalid or expired authorization code")))
                .flatMap(codeData -> authorizationCodeCacheStore.delete(code)
                        .then(Mono.defer(() -> validateAndBuildAuthCodeToken(
                                baseUrl, codeData, redirectUri, codeVerifier, dpopHeader, tokenEndpointUri,
                                attestedClientId))));
    }

    private Mono<TokenResponse> validateAndBuildAuthCodeToken(
            String baseUrl, AuthorizationCodeData codeData, String redirectUri,
            String codeVerifier, String dpopHeader, String tokenEndpointUri, String attestedClientId
    ) {
        if (codeData.redirectUri() != null && !codeData.redirectUri().equals(redirectUri)) {
            return Mono.error(OAuthTokenException.invalidGrant("redirect_uri mismatch"));
        }

        // RFC 6749 4.1.3: the Authorization Server must ensure the authorization code was
        // issued to the client redeeming it. Without this a leaked code could be exchanged by
        // any other client that got hold of it - PKCE and DPoP narrow the window but neither
        // is the binding the RFC asks for.
        if (attestedClientId != null && codeData.clientId() != null
                && !attestedClientId.equals(codeData.clientId())) {
            log.warn("Authorization code redeemed by a different client than it was issued to");
            return Mono.error(OAuthTokenException.invalidGrant(
                    "authorization code was not issued to this client"));
        }

        // PkceVerifier/DpopValidationService raise plain IllegalArgumentException, which
        // Oidc4vciExceptionHandler's generic handler maps to our internal Problem-Details
        // error body instead of the error/error_description shape RFC 6749 section 5.2
        // requires for this endpoint - the same gap ParServiceImpl and
        // AuthorizationServiceImpl already had fixed for their own equivalents.
        //
        // PKCE and DPoP failures are caught separately because they map to different error
        // codes: RFC 7636 section 4.6 mandates invalid_grant specifically for a missing or
        // mismatched code_verifier, while a missing/invalid DPoP proof stays invalid_request.
        if (profileProperties.authorizationCode().requirePkce()) {
            try {
                pkceVerifier.verifyS256(codeVerifier, codeData.codeChallenge());
            } catch (IllegalArgumentException e) {
                return Mono.error(OAuthTokenException.invalidGrant(e.getMessage()));
            }
        }

        String dpopJkt;
        try {
            dpopJkt = profileProperties.authorizationCode().requireDpop()
                    ? dpopValidationService.validate(dpopHeader, "POST", tokenEndpointUri)
                    : null;
        } catch (IllegalArgumentException e) {
            return Mono.error(OAuthTokenException.invalidRequest(e.getMessage()));
        }

        // issuer_state is OPTIONAL at the PAR/authorize level (RFC 9126 / OID4VCI) - a
        // wallet-initiated authorization request never sends it - but this Issuer only
        // resolves the issuanceId an access token is bound to via this lookup, so a code
        // without one can never be exchanged here. Guava's Cache.getIfPresent throws NPE
        // on a null key, which would otherwise surface as a 500 instead of invalid_grant.
        if (codeData.issuerState() == null || codeData.issuerState().isBlank()) {
            return Mono.error(OAuthTokenException.invalidGrant(
                    "Authorization code is not associated with an issuer_state"));
        }

        return issuerStateCacheStore.get(codeData.issuerState())
                .switchIfEmpty(Mono.error(OAuthTokenException.invalidGrant("Invalid or expired issuer_state")))
                .map(issuanceId -> buildAuthCodeTokenResponse(baseUrl, dpopJkt, issuanceId));
    }

    private TokenResponse buildAuthCodeTokenResponse(String baseUrl, String dpopJkt, String issuanceId) {
        Instant issueTime = Instant.now();
        long accessTokenExp = computeAccessTokenExpiration(issueTime);
        boolean isDpop = dpopJkt != null;

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", baseUrl);
        claims.put("aud", baseUrl);
        claims.put("iat", issueTime.getEpochSecond());
        claims.put("exp", accessTokenExp);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("pid", issuanceId);
        if (isDpop) {
            claims.put("cnf", Map.of("jkt", dpopJkt));
        }

        String accessToken = jwtService.issueJWT(new Payload(claims).toString());

        return TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType(isDpop ? TOKEN_TYPE_DPOP : TOKEN_TYPE_BEARER)
                .expiresIn(accessTokenExp - Instant.now().getEpochSecond())
                .refreshToken(null)
                .build();
    }

    // -- Shared --

    private long computeAccessTokenExpiration(Instant issueTime) {
        return issueTime.plus(ACCESS_TOKEN_EXPIRATION_MINUTES, ChronoUnit.MINUTES).getEpochSecond();
    }

    private Mono<Void> storeRefreshToken(String issuanceId, String preAuthorizedCode, String refreshToken, long expiresAt) {
        IssuanceIdAndRefreshToken entry = IssuanceIdAndRefreshToken.builder()
                .preAuthorizedCode(preAuthorizedCode)
                .issuanceId(issuanceId)
                .refreshTokenJti(refreshToken)
                .refreshTokenExpiresAt(expiresAt)
                .build();
        return refreshTokenCacheStore.add(refreshToken, entry).then();
    }
}
