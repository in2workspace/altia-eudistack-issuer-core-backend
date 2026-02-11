package es.in2.issuer.backend.spi.domain.model;

public record SigningContext(
        String token,
        String procedureId,
        String email
) {}