package es.in2.issuer.backend.signing.domain.model.dto;

import java.util.List;

public record CertificateInfo(
        List<String> certificates,
        String issuerDN,
        String subjectDN,
        String serialNumber,
        String validFrom,
        String validTo,
        List<String> keyAlgorithms,
        Integer keyLength
) {}