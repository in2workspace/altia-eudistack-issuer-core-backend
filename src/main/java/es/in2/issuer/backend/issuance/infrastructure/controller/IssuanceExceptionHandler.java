package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
@Order(2)
public class IssuanceExceptionHandler {

    private final ErrorResponseFactory errors;

    @ExceptionHandler(InvalidStatusException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleInvalidStatusException(
            InvalidStatusException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_STATUS.getCode(),
                "Invalid status",
                HttpStatus.CONFLICT,
                "The entity is not in a valid status for this operation"
        );
    }

    @ExceptionHandler(InvalidDeliveryModeException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidDeliveryMode(
            InvalidDeliveryModeException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_REQUEST.getCode(),
                "Invalid request",
                HttpStatus.BAD_REQUEST,
                "The delivery mode is missing, blank or unknown"
        );
    }

    // Also mapped in SharedExceptionHandler (EUD-168 code review): the exception itself lives in the
    // shared package and is thrown by both the issuance path and the backoffice delivery-config PUT,
    // which does not go through this advice in isolated (non-Spring-context) test setups such as
    // DirectDeliveryCeilingTest -- kept here too so the issuance path's own tests stay decoupled from
    // SharedExceptionHandler.
    @ExceptionHandler(DeliveryModeNotEligibleException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleDeliveryModeNotEligible(
            DeliveryModeNotEligibleException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.DELIVERY_MODE_NOT_ELIGIBLE.getCode(),
                "Delivery mode not eligible",
                HttpStatus.CONFLICT,
                "The declared delivery mode is not eligible for this credential type"
        );
    }

    @ExceptionHandler(InvalidHolderKeyException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidHolderKey(
            InvalidHolderKeyException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_HOLDER_KEY.getCode(),
                "Invalid holder key",
                HttpStatus.BAD_REQUEST,
                "The holder key is missing or malformed (expected a jwk member with an EC P-256 public key)"
        );
    }
}
