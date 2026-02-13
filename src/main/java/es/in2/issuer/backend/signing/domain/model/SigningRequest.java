package es.in2.issuer.backend.signing.domain.model;

public record SigningRequest(
        SigningType type,
        String data,
        SigningContext context
) {}