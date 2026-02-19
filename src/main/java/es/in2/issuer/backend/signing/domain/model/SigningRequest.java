package es.in2.issuer.backend.signing.domain.model;

import lombok.Builder;

@Builder
public record SigningRequest(
        SigningType type,
        String data,
        SigningContext context
) {}