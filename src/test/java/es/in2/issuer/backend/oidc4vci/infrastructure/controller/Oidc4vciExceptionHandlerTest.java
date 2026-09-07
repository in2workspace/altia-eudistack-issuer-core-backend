package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.exception.OAuthTokenException;
import es.in2.issuer.backend.oidc4vci.domain.model.NonceResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.exception.InvalidOrMissingProofException;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.oidc4vci.domain.exception.CredentialRequestDeniedException;
import es.in2.issuer.backend.oidc4vci.domain.exception.InvalidNonceException;
import es.in2.issuer.backend.oidc4vci.domain.exception.UnknownCredentialIdentifierException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class Oidc4vciExceptionHandlerTest {

    private ErrorResponseFactory errors;
    private Oidc4vciExceptionHandler handler;
    private ServerHttpRequest request;
    private ServerHttpResponse response;

    @BeforeEach
    void setUp() {
        errors = mock(ErrorResponseFactory.class);
        handler = new Oidc4vciExceptionHandler(errors);
        request = MockServerHttpRequest.get("/any").build();
        response = new MockServerHttpResponse();
    }

    private void assertGem(GlobalErrorMessage gem,
                           String expectedType,
                           String expectedTitle,
                           HttpStatus expectedStatus,
                           String expectedDetail) {
        assertEquals(expectedType, gem.type());
        assertEquals(expectedTitle, gem.title());
        assertEquals(expectedStatus.value(), gem.status());
        assertEquals(expectedDetail, gem.detail());
        assertDoesNotThrow(() -> UUID.fromString(gem.instance()));
    }

    // -------------------- handleOAuthTokenException --------------------

    @Test
    void handleOAuthTokenException_returnsBadRequest() {
        var ex = new OAuthTokenException("invalid_grant", "The grant is invalid");

        StepVerifier.create(handler.handleOAuthTokenException(ex, response))
                .assertNext(body -> {
                    assertEquals("invalid_grant", body.error());
                    assertEquals("The grant is invalid", body.errorDescription());
                })
                .verifyComplete();
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void handleOAuthTokenException_invalidClient_returnsUnauthorized() {
        var ex = OAuthTokenException.invalidClient();

        StepVerifier.create(handler.handleOAuthTokenException(ex, response))
                .assertNext(body -> {
                    assertEquals("invalid_client", body.error());
                    assertEquals("invalid_client", body.errorDescription());
                })
                .verifyComplete();
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    // -------------------- handleInvalidOrMissingProof --------------------

    @Test
    void handleInvalidOrMissingProof_returnsCredentialErrorResponse() {
        var ex = new InvalidOrMissingProofException("bad proof");

        StepVerifier.create(handler.handleInvalidOrMissingProof(ex))
                .assertNext(body -> {
                    assertEquals("invalid_proof", body.error());
                    assertEquals("bad proof", body.errorDescription());
                    assertEquals(null, body.errorUri());
                })
                .verifyComplete();
    }

    // -------------------- handleInvalidNonce --------------------

    // §8.3.1.2 keeps invalid_nonce apart from invalid_proof: the Wallet's recovery is to fetch a
    // fresh nonce and retry, not to treat its own proof as broken.
    @Test
    void handleInvalidNonce_returnsInvalidNonceErrorCode() {
        var ex = new InvalidNonceException("Nonce is invalid or expired");

        StepVerifier.create(handler.handleInvalidNonce(ex))
                .assertNext(body -> {
                    assertEquals("invalid_nonce", body.error());
                    assertEquals("Nonce is invalid or expired", body.errorDescription());
                    assertEquals(null, body.errorUri());
                })
                .verifyComplete();
    }

    // -------------------- handleProofValidationException --------------------

    @Test
    void handleProofValidationException_returnsCredentialErrorResponse() {
        var ex = new ProofValidationException("proof invalid");

        StepVerifier.create(handler.handleProofValidationException(ex))
                .assertNext(body -> {
                    assertEquals("invalid_proof", body.error());
                    assertEquals("proof invalid", body.errorDescription());
                    assertEquals(null, body.errorUri());
                })
                .verifyComplete();
    }

    // -------------------- handleUnknownCredentialConfiguration --------------------

    @Test
    void handleUnknownCredentialConfiguration_returnsCredentialErrorResponseWithoutNonce() {
        var ex = new UnknownCredentialConfigurationException("Unknown credential_configuration_id: bogus");

        StepVerifier.create(handler.handleUnknownCredentialConfiguration(ex))
                .assertNext(body -> {
                    assertEquals("unknown_credential_configuration", body.error());
                    assertEquals("Unknown credential_configuration_id: bogus", body.errorDescription());
                    assertEquals(null, body.errorUri());
                })
                .verifyComplete();

    }

    // -------------------- handleCredentialRequestDenied --------------------

    @Test
    void handleCredentialRequestDenied_returnsCredentialErrorResponseWithoutNonce() {
        var ex = new CredentialRequestDeniedException("Issuance is no longer issuable: REVOKED");

        StepVerifier.create(handler.handleCredentialRequestDenied(ex))
                .assertNext(body -> {
                    assertEquals("credential_request_denied", body.error());
                    assertEquals("Issuance is no longer issuable: REVOKED", body.errorDescription());
                    assertEquals(null, body.errorUri());
                })
                .verifyComplete();

    }

    // -------------------- handleUnknownCredentialIdentifier --------------------

    @Test
    void handleUnknownCredentialIdentifier_returnsCredentialErrorResponseWithoutNonce() {
        var ex = new UnknownCredentialIdentifierException("Unknown credential_identifier: bogus");

        StepVerifier.create(handler.handleUnknownCredentialIdentifier(ex))
                .assertNext(body -> {
                    assertEquals("unknown_credential_identifier", body.error());
                    assertEquals("Unknown credential_identifier: bogus", body.errorDescription());
                    assertEquals(null, body.errorUri());
                })
                .verifyComplete();

    }

    // -------------------- handleInvalidHolderKey (EUD-168 TD-14) --------------------

    @Test
    void handleInvalidHolderKey_returnsCredentialRequestDeniedWithGenericDescription() {
        var ex = new InvalidHolderKeyException("invalid holder_key: jwk must be a non-empty JSON object");

        StepVerifier.create(handler.handleInvalidHolderKey(ex))
                .assertNext(body -> {
                    assertEquals("credential_request_denied", body.error());
                    // F4: must NOT echo ex.getMessage() -- that wording describes holder_key, a
                    // field this endpoint's own request never carries.
                    assertEquals("The credential cannot be issued for this request", body.errorDescription());
                    assertEquals(null, body.errorUri());
                })
                .verifyComplete();
    }

    // -------------------- handleIllegalArgumentException --------------------

    @Test
    void handleIllegalArgumentException_returnsBadRequest() {
        var ex = new IllegalArgumentException("Missing DPoP proof");
        var type = GlobalErrorTypes.INVALID_REQUEST.getCode();
        var title = "Invalid request";
        var st = HttpStatus.BAD_REQUEST;
        var expected = new GlobalErrorMessage(type, title, st.value(), "Missing DPoP proof", UUID.randomUUID().toString());

        when(errors.handleWith(ex, request, type, title, st, "Missing DPoP proof")).thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleIllegalArgumentException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "Missing DPoP proof"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, "Missing DPoP proof");
    }

}
