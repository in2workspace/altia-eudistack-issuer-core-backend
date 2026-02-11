package es.in2.issuer.backend.spi.domain.model;

import java.util.Map;

public record SigningRequest(
        SigningType type,
        String data,
        SigningContext context
) {}