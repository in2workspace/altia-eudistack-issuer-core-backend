package es.in2.issuer.backend.signing.domain.exception;

public class SigningException extends RuntimeException {
    public SigningException(String message) { super(message); }
    public SigningException(String message, Throwable cause) { super(message, cause); }
}
