package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class IssuanceExceptionHandlerTest {

    private ErrorResponseFactory errors;
    private IssuanceExceptionHandler handler;
    private ServerHttpRequest request;

    @BeforeEach
    void setUp() {
        errors = mock(ErrorResponseFactory.class);
        handler = new IssuanceExceptionHandler(errors);
        request = MockServerHttpRequest.get("/any").build();
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

    // ------------------- InvalidStatusException -------------------

    @Test
    void handleInvalidStatusException_usesExceptionMessage_whenPresent() {
        var ex = new InvalidStatusException("invalid status: REVOKED");

        String type   = GlobalErrorTypes.INVALID_STATUS.getCode();
        String title  = "Invalid status";
        HttpStatus st = HttpStatus.CONFLICT;
        String fallback = "The entity is not in a valid status for this operation";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidStatusException(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "invalid status: REVOKED"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleInvalidStatusException_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new InvalidStatusException(null);
        var exBlank = new InvalidStatusException("");

        String type   = GlobalErrorTypes.INVALID_STATUS.getCode();
        String title  = "Invalid status";
        HttpStatus st = HttpStatus.CONFLICT;
        String fallback = "The entity is not in a valid status for this operation";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleInvalidStatusException(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleInvalidStatusException(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // ------------------- InvalidDeliveryModeException (ES-01) -------------------

    @Test
    void handleInvalidDeliveryMode_usesExceptionMessage_whenPresent() {
        var ex = new InvalidDeliveryModeException("Unknown delivery mode: carrier-pigeon");

        String type   = GlobalErrorTypes.INVALID_REQUEST.getCode();
        String title  = "Invalid request";
        HttpStatus st = HttpStatus.BAD_REQUEST;
        String fallback = "The delivery mode is missing, blank or unknown";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidDeliveryMode(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st, "Unknown delivery mode: carrier-pigeon"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleInvalidDeliveryMode_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new InvalidDeliveryModeException(null);
        var exBlank = new InvalidDeliveryModeException("");

        String type   = GlobalErrorTypes.INVALID_REQUEST.getCode();
        String title  = "Invalid request";
        HttpStatus st = HttpStatus.BAD_REQUEST;
        String fallback = "The delivery mode is missing, blank or unknown";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleInvalidDeliveryMode(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleInvalidDeliveryMode(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // ------------------- DeliveryModeNotEligibleException (AC-05) -------------------

    @Test
    void handleDeliveryModeNotEligible_usesExceptionMessage_whenPresent() {
        var ex = new DeliveryModeNotEligibleException(
                "Delivery mode 'direct' is not eligible for credential type: learcredential.employee.w3c.4");

        String type   = GlobalErrorTypes.DELIVERY_MODE_NOT_ELIGIBLE.getCode();
        String title  = "Delivery mode not eligible";
        HttpStatus st = HttpStatus.CONFLICT;
        String fallback = "The declared delivery mode is not eligible for this credential type";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleDeliveryModeNotEligible(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st,
                        "Delivery mode 'direct' is not eligible for credential type: learcredential.employee.w3c.4"))
                .verifyComplete();

        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleDeliveryModeNotEligible_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new DeliveryModeNotEligibleException(null);
        var exBlank = new DeliveryModeNotEligibleException("");

        String type   = GlobalErrorTypes.DELIVERY_MODE_NOT_ELIGIBLE.getCode();
        String title  = "Delivery mode not eligible";
        HttpStatus st = HttpStatus.CONFLICT;
        String fallback = "The declared delivery mode is not eligible for this credential type";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleDeliveryModeNotEligible(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleDeliveryModeNotEligible(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

    // ------------------- InvalidHolderKeyException -------------------

    @Test
    void handleInvalidHolderKey_mapsTo400InvalidHolderKey_usingExceptionMessage() {
        var ex = new InvalidHolderKeyException("invalid holder_key: expected a jwk member");

        String type   = GlobalErrorTypes.INVALID_HOLDER_KEY.getCode();
        String title  = "Invalid holder key";
        HttpStatus st = HttpStatus.BAD_REQUEST;
        String fallback = "The holder key is missing or malformed (expected a jwk member with an EC P-256 public key)";

        var expected = new GlobalErrorMessage(type, title, st.value(), ex.getMessage(), UUID.randomUUID().toString());
        when(errors.handleWith(ex, request, type, title, st, fallback))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(handler.handleInvalidHolderKey(ex, request))
                .assertNext(gem -> assertGem(gem, type, title, st,
                        "invalid holder_key: expected a jwk member"))
                .verifyComplete();

        assertEquals("invalid_holder_key", type);
        verify(errors).handleWith(ex, request, type, title, st, fallback);
    }

    @Test
    void handleInvalidHolderKey_usesFallback_whenMessageNullOrBlank() {
        var exNull  = new InvalidHolderKeyException(null);
        var exBlank = new InvalidHolderKeyException("");

        String type   = GlobalErrorTypes.INVALID_HOLDER_KEY.getCode();
        String title  = "Invalid holder key";
        HttpStatus st = HttpStatus.BAD_REQUEST;
        String fallback = "The holder key is missing or malformed (expected a jwk member with an EC P-256 public key)";

        var expectedNull  = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());
        var expectedBlank = new GlobalErrorMessage(type, title, st.value(), fallback, UUID.randomUUID().toString());

        when(errors.handleWith(exNull,  request, type, title, st, fallback)).thenReturn(Mono.just(expectedNull));
        when(errors.handleWith(exBlank, request, type, title, st, fallback)).thenReturn(Mono.just(expectedBlank));

        StepVerifier.create(handler.handleInvalidHolderKey(exNull, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        StepVerifier.create(handler.handleInvalidHolderKey(exBlank, request))
                .assertNext(gem -> assertGem(gem, type, title, st, fallback))
                .verifyComplete();

        verify(errors).handleWith(exNull,  request, type, title, st, fallback);
        verify(errors).handleWith(exBlank, request, type, title, st, fallback);
    }

}
