package es.in2.issuer.backend.signing.infrastructure.csc.v2.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record CscV2SignHashRequest(
        @JsonProperty("credentialID")     String credentialId,
        @JsonProperty("SAD")              String sad,
        @JsonProperty("hashes")           List<String> hashes,
        @JsonProperty("hashAlgorithmOID") String hashAlgorithmOID,
        @JsonProperty("signAlgo")         String signAlgo
) {}
