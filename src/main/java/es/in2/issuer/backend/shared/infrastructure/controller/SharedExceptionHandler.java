package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.signing.domain.exception.SigningResultParsingException;
import es.in2.issuer.backend.statuslist.domain.exception.SignedStatusListCredentialNotAvailableException;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

import javax.naming.OperationNotSupportedException;
import java.text.ParseException;
import java.util.NoSuchElementException;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
@Order(Ordered.LOWEST_PRECEDENCE)
public class SharedExceptionHandler {

    private final ErrorResponseFactory errors;

    @ExceptionHandler(RemoteSignatureException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public Mono<GlobalErrorMessage> handleRemoteSignatureException(
            RemoteSignatureException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.REMOTE_SIGNATURE.getCode(),
                "Remote signature error",
                HttpStatus.BAD_GATEWAY,
                "An error occurred during remote signature operation"
        );
    }

    @ExceptionHandler(CredentialTypeUnsupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleCredentialTypeUnsupported(
            CredentialTypeUnsupportedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_TYPE.getCode(),
                "Unsupported credential type",
                HttpStatus.BAD_REQUEST,
                "The given credential_configuration_id is not supported by this issuer"
        );
    }

    @ExceptionHandler(InvalidCredentialRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidCredentialRequest(
            InvalidCredentialRequestException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_CREDENTIAL_REQUEST.getCode(),
                "Invalid credential request",
                HttpStatus.BAD_REQUEST,
                "The credential request is malformed or contains invalid parameters"
        );
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoSuchElementException(
            NoSuchElementException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.NO_SUCH_ELEMENT.getCode(),
                "Resource not found",
                HttpStatus.NOT_FOUND,
                "The requested resource was not found"
        );
    }

    @ExceptionHandler(InvalidTokenException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<GlobalErrorMessage> handleInvalidToken(
            InvalidTokenException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_TOKEN.getCode(),
                "Invalid token",
                HttpStatus.UNAUTHORIZED,
                "Credential Request contains the wrong Access Token or the Access Token is missing"
        );
    }

    @ExceptionHandler(ParseException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleParseException(
            ParseException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Parse error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal parsing error occurred."
        );
    }

    @ExceptionHandler(Base45Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleBase45Exception(
            Base45Exception ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Base45 decoding error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal Base45 decoding error occurred."
        );
    }

    @ExceptionHandler(SigningResultParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleSigningResultParsingException(
            SigningResultParsingException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Signing result parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal signing result parsing error occurred."
        );
    }

    @ExceptionHandler(ParseCredentialJsonException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleParseCredentialJsonException(
            ParseCredentialJsonException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR.getCode(),
                "Credential JSON parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An internal credential JSON parsing error occurred."
        );
    }

    @ExceptionHandler(NoCredentialFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleNoCredentialFoundException(
            NoCredentialFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_NOT_FOUND.getCode(),
                "Credential not found",
                HttpStatus.NOT_FOUND,
                "No credential found."
        );
    }

    @ExceptionHandler(PreAuthorizationCodeGetException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handlePreAuthorizationCodeGetException(
            PreAuthorizationCodeGetException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PRE_AUTHORIZATION_CODE_GET.getCode(),
                "Pre-authorization code retrieval error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Failed to retrieve pre-authorization code."
        );
    }

    @ExceptionHandler(CredentialOfferNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleCredentialOfferNotFoundException(
            CredentialOfferNotFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_OFFER_NOT_FOUND.getCode(),
                "Credential offer not found",
                HttpStatus.NOT_FOUND,
                "Credential offer not found."
        );
    }

    @ExceptionHandler(CredentialAlreadyIssuedException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleCredentialAlreadyIssuedException(
            CredentialAlreadyIssuedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_ALREADY_ISSUED.getCode(),
                "Credential already issued",
                HttpStatus.CONFLICT,
                "The credential has already been issued."
        );
    }

    @ExceptionHandler(OperationNotSupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleOperationNotSupportedException(
            OperationNotSupportedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.OPERATION_NOT_SUPPORTED.getCode(),
                "Operation not supported",
                HttpStatus.BAD_REQUEST,
                "The given operation is not supported"
        );
    }

    @ExceptionHandler(JWTVerificationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Mono<GlobalErrorMessage> handleJWTVerificationException(
            JWTVerificationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.JWT_VERIFICATION.getCode(),
                "JWT verification failed",
                HttpStatus.UNAUTHORIZED,
                "JWT verification failed."
        );
    }

    @ExceptionHandler(FormatUnsupportedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleFormatUnsupportedException(
            FormatUnsupportedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNSUPPORTED_CREDENTIAL_FORMAT.getCode(),
                "Format not supported",
                HttpStatus.BAD_REQUEST,
                "Format is not supported"
        );
    }

    @ExceptionHandler(InsufficientPermissionException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleInsufficientPermissionException(
            InsufficientPermissionException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INSUFFICIENT_PERMISSION.getCode(),
                "Insufficient permission",
                HttpStatus.FORBIDDEN,
                "The client who made the issuance request do not have the required permissions"
        );
    }

    @ExceptionHandler(UnauthorizedRoleException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleUnauthorizedRoleException(
            UnauthorizedRoleException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNAUTHORIZED_ROLE.getCode(),
                "Unauthorized role",
                HttpStatus.FORBIDDEN,
                "The user role is not authorized to perform this action"
        );
    }

    @ExceptionHandler(InvalidCredentialStatusTransitionException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleInvalidCredentialStatusTransitionException(
            InvalidCredentialStatusTransitionException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_CREDENTIAL_STATUS_TRANSITION.getCode(),
                "Invalid credential status transition",
                HttpStatus.CONFLICT,
                "The credential is not in a status that allows this transition"
        );
    }

    @ExceptionHandler(EmailCommunicationException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public Mono<GlobalErrorMessage> handleEmailCommunicationException(
            EmailCommunicationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.EMAIL_COMMUNICATION.getCode(),
                "Email communication error",
                HttpStatus.SERVICE_UNAVAILABLE,
                "Email communication failed"
        );
    }

    @ExceptionHandler(MissingIdTokenHeaderException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleMissingIdTokenHeaderException(
            MissingIdTokenHeaderException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.MISSING_HEADER.getCode(),
                "Missing header",
                HttpStatus.BAD_REQUEST,
                "The X-ID-TOKEN header is missing, this header is needed to issue a Verifiable Certification"
        );
    }

    @ExceptionHandler(SadException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public Mono<GlobalErrorMessage> handleSadException(
            SadException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.SAD_ERROR.getCode(),
                "SAD error",
                HttpStatus.BAD_GATEWAY,
                "An upstream SAD error occurred"
        );
    }

    @ExceptionHandler(CredentialSerializationException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleCredentialSerializationException(
            CredentialSerializationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_SERIALIZATION.getCode(),
                "Credential serialization error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An error occurred during credential serialization"
        );
    }

    @ExceptionHandler(JWTParsingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Mono<GlobalErrorMessage> handleJWTParsingException(
            JWTParsingException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_JWT.getCode(),
                "JWT parsing error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "The provided JWT is invalid or can't be parsed."
        );
    }

    @ExceptionHandler(IssuanceInvalidStatusException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleIssuanceInvalidStatusException(
            IssuanceInvalidStatusException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.ISSUANCE_INVALID_STATUS.getCode(),
                "Invalid issuance status",
                HttpStatus.CONFLICT,
                "The issuance is not in a status that allows signing."
        );
    }

    @ExceptionHandler(IssuanceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleIssuanceNotFoundException(
            IssuanceNotFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.ISSUANCE_NOT_FOUND.getCode(),
                "Issuance not found",
                HttpStatus.NOT_FOUND,
                "The requested issuance was not found"
        );
    }

    @ExceptionHandler(TenantMismatchException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleTenantMismatchException(
            TenantMismatchException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.TENANT_MISMATCH.getCode(),
                "Tenant mismatch",
                HttpStatus.FORBIDDEN,
                "The token's organization does not match the requested tenant"
        );
    }

    @ExceptionHandler(TenantNotResolvedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Mono<GlobalErrorMessage> handleTenantNotResolvedException(
            TenantNotResolvedException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.TENANT_NOT_RESOLVED.getCode(),
                "Tenant not resolved",
                HttpStatus.FORBIDDEN,
                "The operation requires a resolved tenant and none could be determined for this request"
        );
    }

    @ExceptionHandler(PayloadValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handlePayloadValidationException(
            PayloadValidationException ex,
            ServerHttpRequest request
    ) {
        var violations = ex.getViolations().stream()
                .map(v -> new GlobalErrorMessage.FieldViolation(v.field(), v.message()))
                .toList();
        return errors.handleWithViolations(
                ex, request,
                GlobalErrorTypes.PAYLOAD_VALIDATION.getCode(),
                "Payload validation failed",
                HttpStatus.BAD_REQUEST,
                "The credential payload does not conform to the required schema",
                violations
        );
    }

    @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class)
    public Mono<org.springframework.http.ResponseEntity<GlobalErrorMessage>> handleResponseStatusException(
            org.springframework.web.server.ResponseStatusException ex,
            ServerHttpRequest request
    ) {
        HttpStatus status = HttpStatus.resolve(ex.getStatusCode().value());
        if (status == null) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }
        HttpStatus finalStatus = status;
        return errors.handleWith(
                ex, request,
                status.name(),
                status.getReasonPhrase(),
                status,
                ex.getReason() != null ? ex.getReason() : status.getReasonPhrase()
        ).map(body -> org.springframework.http.ResponseEntity.status(finalStatus).body(body));
    }

    @ExceptionHandler(StatusListNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleStatusListNotFoundException(
            StatusListNotFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.STATUS_LIST_NOT_FOUND.getCode(),
                "Status list not found",
                HttpStatus.NOT_FOUND,
                "The requested status list was not found"
        );
    }

    @ExceptionHandler(SignedStatusListCredentialNotAvailableException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleSignedStatusListNotAvailable(
            SignedStatusListCredentialNotAvailableException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.STATUS_LIST_NOT_AVAILABLE.getCode(),
                "Status list credential not available",
                HttpStatus.NOT_FOUND,
                "The signed status list credential is not yet available"
        );
    }

    // SEC-13: Catch-all handler — never leaks internal details to the client
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @Order
    public Mono<GlobalErrorMessage> handleUnexpectedException(
            Exception ex,
            ServerHttpRequest request
    ) {
        return errors.handleSafe(
                ex, request,
                "INTERNAL_SERVER_ERROR",
                "Internal server error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred"
        );
    }

    @ExceptionHandler(UnknownCredentialConfigurationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleUnknownCredentialConfiguration(
            UnknownCredentialConfigurationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.UNKNOWN_CREDENTIAL_CONFIGURATION.getCode(),
                "Unknown credential configuration",
                HttpStatus.BAD_REQUEST,
                "The request references one or more credential_configuration_id values that do not exist in the global credential profile registry"
        );
    }

    @ExceptionHandler(CredentialCatalogNotConfiguredException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleCredentialCatalogNotConfigured(
            CredentialCatalogNotConfiguredException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.CREDENTIAL_CATALOG_NOT_CONFIGURED.getCode(),
                "Credential catalog not configured",
                HttpStatus.NOT_FOUND,
                "No credential configuration is enabled for this tenant"
        );
    }

    @ExceptionHandler(InvalidCredentialFormatException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidCredentialFormatException(
            InvalidCredentialFormatException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_CREDENTIAL_FORMAT.getCode(),
                "Invalid credential format",
                HttpStatus.BAD_REQUEST,
                "The given credential format is invalid"
        );
    }

    @ExceptionHandler(DidKeyCreationException.class)
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    public Mono<GlobalErrorMessage> handleDidKeyCreationException(
            DidKeyCreationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.DID_KEY_CREATION_ERROR.getCode(),
                "DID key creation error",
                HttpStatus.UNPROCESSABLE_ENTITY,
                "An error occurred during DID key creation"
        );
    }

    @ExceptionHandler(ECKeyCreationException.class)
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    public Mono<GlobalErrorMessage> handleECKeyCreationException(
            ECKeyCreationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.EC_KEY_CREATION_ERROR.getCode(),
                "EC key creation error",
                HttpStatus.UNPROCESSABLE_ENTITY,
                "An error occurred during EC key creation"
        );
    }

    @ExceptionHandler(JWTClaimMissingException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleJWTClaimMissingException(
            JWTClaimMissingException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.JWT_CLAIM_MISSING_ERROR.getCode(),
                "JWT claim missing error",
                HttpStatus.BAD_REQUEST,
                "A required claim is missing in the provided JWT."
        );
    }

    @ExceptionHandler(JWTCreationException.class)
    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    public Mono<GlobalErrorMessage> handleJWTCreationException(
            JWTCreationException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.JWT_CREATION_ERROR.getCode(),
                "JWT creation error",
                HttpStatus.UNPROCESSABLE_ENTITY,
                "An error occurred during JWT creation."
        );
    }

    @ExceptionHandler(MissingCredentialTypeException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleMissingCredentialTypeException(
            MissingCredentialTypeException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.MISSING_CREDENTIAL_TYPE_ERROR.getCode(),
                "Missing credential type error",
                HttpStatus.BAD_REQUEST,
                "The credential type is missing in the request."
        );
    }

    @ExceptionHandler(MissingEmailOwnerException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleMissingEmailOwnerException(
            MissingEmailOwnerException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.MISSING_EMAIL_OWNER_ERROR.getCode(),
                "Missing email owner error",
                HttpStatus.BAD_REQUEST,
                "The email owner is missing in the request."
        );
    }

    @ExceptionHandler(ParseErrorException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleParseErrorException(
            ParseErrorException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.PARSE_ERROR_EXCEPTION.getCode(),
                "Parse error exception",
                HttpStatus.BAD_REQUEST,
                "An internal parsing error occurred."
        );
    }

    @ExceptionHandler(TokenFetchException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public Mono<GlobalErrorMessage> handleTokenFetchException(
            TokenFetchException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.TOKEN_FETCH_ERROR.getCode(),
                "Token fetch error",
                HttpStatus.BAD_GATEWAY,
                "An error occurred while fetching token."
        );
    }

    @ExceptionHandler(WellKnownInfoFetchException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public Mono<GlobalErrorMessage> handleWellKnownInfoFetchException(
            WellKnownInfoFetchException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.WELL_KNOWN_INFO_FETCH_ERROR.getCode(),
                "Well-known info fetch error",
                HttpStatus.BAD_GATEWAY,
                "An error occurred while fetching well-known information."
        );
    }

    @ExceptionHandler(InvalidDeliveryConfigException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Mono<GlobalErrorMessage> handleInvalidDeliveryConfigException(
            InvalidDeliveryConfigException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.INVALID_DELIVERY_CONFIG.getCode(),
                "Invalid delivery configuration",
                HttpStatus.BAD_REQUEST,
                "The requested eligible delivery modes are invalid"
        );
    }

    @ExceptionHandler(DeliveryConfigProfileNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Mono<GlobalErrorMessage> handleDeliveryConfigProfileNotFoundException(
            DeliveryConfigProfileNotFoundException ex,
            ServerHttpRequest request
    ) {
        return errors.handleWith(
                ex, request,
                GlobalErrorTypes.DELIVERY_CONFIG_PROFILE_NOT_FOUND.getCode(),
                "Delivery config profile not found",
                HttpStatus.NOT_FOUND,
                "The given credential_configuration_id is unknown or not enabled for this tenant"
        );
    }

    // Shared rather than issuance-only (EUD-168 code review): thrown from both the issuance path
    // (SchemaDeliveryCeiling.validateWithinCeiling) and the backoffice delivery-config PUT
    // (TenantDeliveryConfigServiceImpl), matching where the exception class itself lives.
    @ExceptionHandler(DeliveryModeNotEligibleException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Mono<GlobalErrorMessage> handleDeliveryModeNotEligibleException(
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
}
