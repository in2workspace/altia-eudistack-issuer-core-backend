package es.in2.issuer.backend.spi.domain.model;

public record SigningResult(
        SigningType type,
        String data
) {}