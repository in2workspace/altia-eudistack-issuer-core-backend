package es.in2.issuer.backend.spi.domain.model;

import java.util.Map;

public record SigningRequest(
        SigningType type,
        String payloadToSign,
        Map<String, Object> options,
        SigningContext context
) {}