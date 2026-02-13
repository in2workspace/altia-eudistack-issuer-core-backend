package es.in2.issuer.backend.signing.domain.model;

public record SigningContext(
        String token,
        String procedureId,
        String email
) {}