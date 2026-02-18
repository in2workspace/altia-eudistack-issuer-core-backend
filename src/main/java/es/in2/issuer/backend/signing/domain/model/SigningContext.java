package es.in2.issuer.backend.signing.domain.model;

import lombok.Builder;

@Builder
public record SigningContext(
        String token,
        String procedureId,
        String email
) {}