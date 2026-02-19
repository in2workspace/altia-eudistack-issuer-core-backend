package es.in2.issuer.backend.signing.domain.model;

public record SigningResult(
        SigningType type,
        String data
) {}