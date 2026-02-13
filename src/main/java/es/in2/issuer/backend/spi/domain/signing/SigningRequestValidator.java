package es.in2.issuer.backend.spi.domain.signing;

import es.in2.issuer.backend.spi.domain.exception.SigningException;
import es.in2.issuer.backend.spi.domain.model.SigningRequest;

public final class SigningRequestValidator {

    private SigningRequestValidator() {}

    public static void validate(SigningRequest request) {
        if (request == null) {
            throw new SigningException("SigningRequest must not be null");
        }
        if (request.type() == null) {
            throw new SigningException("SigningRequest.type must not be null");
        }
        if (request.data() == null || request.data().isBlank()) {
            throw new SigningException("SigningRequest.data must not be null/blank");
        }
        if (request.context() == null) {
            throw new SigningException("SigningRequest.context must not be null");
        }
        if (request.context().token() == null || request.context().token().isBlank()) {
            throw new SigningException("SigningContext.token must not be null/blank");
        }
    }
}
