package es.in2.issuer.backend.signing.infrastructure.csc.v2.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CscV2CredentialsListRequest(
        @JsonProperty("credentialInfo") boolean credentialInfo,
        @JsonProperty("certificates")   String certificates,
        @JsonProperty("certInfo")       boolean certInfo,
        @JsonProperty("authInfo")       boolean authInfo,
        @JsonProperty("onlyValid")      boolean onlyValid,
        // CSC v2.1.0.1 §8.2 defines `lang` as a string (RFC 5646). Typed as
        // Object because Digitel's QTSP rejects the spec-conformant string
        // with a 500 and only accepts the pre-conformance int — see
        // CscV2Adapter.DIGITEL_PROVIDER.
        @JsonProperty("lang")           Object lang,
        @JsonProperty("clientData")     String clientData
) {}
