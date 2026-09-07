package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialErrorResponse;
import es.in2.issuer.backend.oidc4vci.domain.model.OAuthErrorResponse;
import es.in2.issuer.backend.shared.domain.exception.InvalidOrMissingProofException;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.oidc4vci.domain.exception.UnknownCredentialIdentifierException;
import es.in2.issuer.backend.oidc4vci.domain.exception.CredentialRequestDeniedException;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNonceException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

@Slf4j
// Scoped to this package only: IllegalArgumentException is also thrown for internal/
// unrelated reasons elsewhere in the app (signing, status list, tenant config...), where
// it must stay a 500. Only the OID4VCI protocol endpoints (PAR, token, credential, nonce...)
// should treat it as a client input error.
@RestControllerAdvice(basePackages = "es.in2.issuer.backend.oidc4vci.infrastructure.controller")
@RequiredArgsConstructor
@Order(1)
public class Oidc4vciExceptionHandler {

    private final ErrorResponseFactory errors;

    @ExceptionHandler(OAuthTokenException.class)
    public Mono<OAuthErrorResponse> handleOAuthTokenException(OAuthTokenException ex, ServerHttpResponse response) {
        // invalid_client is the only OAuth2 §5.2 error this endpoint returns as 401
        // (client authentication failure); every other error code stays 400.
        HttpStatus status = OAuthTokenException.INVALID_CLIENT.equals(ex.getErrorCode())
                ? HttpStatus.UNAUTHORIZED
                : HttpStatus.BAD_REQUEST;
        response.setStatusCode(status);
        log.warn("OAuth token error: error={}, description={}", ex.getErrorCode(), ex.getMessage());
        return Mono.just(new OAuthErrorResponse(ex.getErrorCode(), ex.getMessage()));
    }

    // OID4VCI 1.0 §8.3.2: the credential endpoint's error body is {error, error_description,
    // error_uri} - a distinct shape from RFC 6749/9126's OAuth2 endpoints and from our internal
    // Problem-Details GlobalErrorMessage. A missing, malformed or unverifiable proof maps to
    // "invalid_proof"; a proof carrying an unrecognized c_nonce has its own code, below.
    private static final String INVALID_PROOF_ERROR = "invalid_proof";

    @ExceptionHandler(InvalidOrMissingProofException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<CredentialErrorResponse> handleInvalidOrMissingProof(InvalidOrMissingProofException ex) {
        log.warn("Invalid or missing proof: {}", ex.getMessage());
        return Mono.just(new CredentialErrorResponse(INVALID_PROOF_ERROR, ex.getMessage()));
    }

    @ExceptionHandler(ProofValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<CredentialErrorResponse> handleProofValidationException(ProofValidationException ex) {
        log.warn("Proof validation error: {}", ex.getMessage());
        return Mono.just(new CredentialErrorResponse(INVALID_PROOF_ERROR, ex.getMessage()));
    }

    // §8.3.1.2 invalid_nonce: the proof carries a c_nonce this Issuer does not recognize or that
    // has expired. Kept apart from invalid_proof because the Wallet's recovery differs - it
    // should fetch a fresh nonce from the Nonce Endpoint and retry, not treat the proof as bad.
    @ExceptionHandler(InvalidNonceException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<CredentialErrorResponse> handleInvalidNonce(InvalidNonceException ex) {
        log.warn("Invalid nonce: {}", ex.getMessage());
        return Mono.just(new CredentialErrorResponse("invalid_nonce", ex.getMessage()));
    }

    // Scoped override of SharedExceptionHandler's GlobalErrorMessage-shaped mapping (used
    // elsewhere for the backoffice credential catalog): within oidc4vci controllers this
    // exception means an unknown credential_configuration_id was requested at /credential,
    // which needs the OID4VCI error shape instead. "unknown_credential_configuration" is the
    // exact code OID4VCI 1.0 SS8.3.1.2 defines for this case - "unsupported_credential_type"
    // is not a recognized code at all and was flagged by the conformance suite as
    // non-standard. No c_nonce - unlike invalid_proof, this error carries no nonce-refresh
    // semantics.
    @ExceptionHandler(UnknownCredentialConfigurationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<CredentialErrorResponse> handleUnknownCredentialConfiguration(UnknownCredentialConfigurationException ex) {
        log.warn("Unknown credential configuration requested");
        return Mono.just(new CredentialErrorResponse("unknown_credential_configuration", ex.getMessage()));
    }

    // credential_identifier is a recognized but permanently unsupported addressing mode - see
    // CredentialRequest and Oid4VciCredentialWorkflowImpl for why. Same OID4VCI error shape,
    // no c_nonce, distinct error code per SS8.3.1.2.
    @ExceptionHandler(UnknownCredentialIdentifierException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<CredentialErrorResponse> handleUnknownCredentialIdentifier(UnknownCredentialIdentifierException ex) {
        log.warn("Unknown credential identifier requested");
        return Mono.just(new CredentialErrorResponse("unknown_credential_identifier", ex.getMessage()));
    }

    // §8.3.1.2 credential_request_denied: the request was well-formed and authorized, but the
    // Issuance is withdrawn, revoked, expired or archived. Unrecoverable, so no c_nonce is
    // offered — a fresh nonce would only invite a retry that cannot succeed.
    @ExceptionHandler(CredentialRequestDeniedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<CredentialErrorResponse> handleCredentialRequestDenied(CredentialRequestDeniedException ex) {
        log.warn("Credential request denied: {}", ex.getMessage());
        return Mono.just(new CredentialErrorResponse("credential_request_denied", ex.getMessage()));
    }

    // EUD-168 TD-14: HolderCnfJson.readValidated (called from Oid4VciCredentialWorkflowImpl.
    // resolveCnf) re-validates a persisted holder_cnf before signing and throws this when the
    // stored value is not a well-formed EC P-256 jwk. Before this handler existed, the exception
    // fell through to the generic IssuanceExceptionHandler advice and reached the wallet as a
    // GlobalErrorMessage (Problem-Details) with 400 and HolderKey's own write-side wording ("...
    // expected a jwk member"), which describes a field this endpoint's request never has -- non-
    // conformant with SS8.3.2's {error, error_description} shape and misleading about what went
    // wrong. The wallet's request is well-formed; the defect is server-side stored data the wallet
    // cannot fix by retrying, so this is credential_request_denied like the Issuance-state case
    // above, not invalid_proof/invalid_request. Generic description on purpose (F4): the wallet's
    // request never carries a holder_key at this endpoint, so echoing HolderKey's own message here
    // would describe the wrong API's field to the wrong actor.
    @ExceptionHandler(InvalidHolderKeyException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<CredentialErrorResponse> handleInvalidHolderKey(InvalidHolderKeyException ex) {
        log.warn("Stored holder cnf failed re-validation: {}", ex.getMessage());
        return Mono.just(new CredentialErrorResponse("credential_request_denied",
                "The credential cannot be issued for this request"));
    }

    // Raised by ParServiceImpl, DpopValidationService, ClientAttestationValidationService and
    // PkceVerifier for malformed/invalid client input (missing DPoP proof, bad client attestation,
    // PKCE mismatch, etc.). Per RFC 9126 §2.3 a bad Pushed Authorization Request — and, by the
    // same reasoning, a bad token request — must yield a 400 OAuth error, not a 500. Scoped to
    // this advice (see class-level Javadoc) so it doesn't reclassify unrelated IllegalArgumentException
    // uses elsewhere in the app.
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleIllegalArgumentException(
            IllegalArgumentException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_REQUEST.getCode(),
                "Invalid request",
                HttpStatus.BAD_REQUEST,
                ex.getMessage()
        );
    }
}