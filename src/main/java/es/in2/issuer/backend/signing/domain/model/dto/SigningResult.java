package es.in2.issuer.backend.signing.domain.model.dto;

import es.in2.issuer.backend.signing.domain.model.SigningType;

public record SigningResult(
        SigningType type,
        String data
) {}