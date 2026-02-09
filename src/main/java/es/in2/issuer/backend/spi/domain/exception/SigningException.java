package es.in2.issuer.backend.spi.domain.exception;

public class SigningException extends RuntimeException {

    public SigningException ( String message, Throwable cause ) {
        super(message, cause);
    }
}
