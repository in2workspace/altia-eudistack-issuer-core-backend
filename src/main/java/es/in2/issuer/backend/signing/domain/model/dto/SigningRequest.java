package es.in2.issuer.backend.signing.domain.model.dto;

import es.in2.issuer.backend.signing.domain.model.SigningType;
import lombok.Builder;

@Builder
public record SigningRequest(
        SigningType type,
        String data,
        SigningContext context
) {}