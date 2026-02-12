package es.in2.issuer.backend.spi.domain.model;

public record SigningRequest(
        SigningType type,
        String data,
        SigningContext context
) {}