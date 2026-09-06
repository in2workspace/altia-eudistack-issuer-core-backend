package es.in2.issuer.backend.signing.infrastructure.csc.v2.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CscV2CredentialsListRequest(
        @JsonProperty("credentialInfo") boolean credentialInfo,
        @JsonProperty("certificates")   String certificates,
        @JsonProperty("certInfo")       boolean certInfo,
        @JsonProperty("authInfo")       boolean authInfo,
        @JsonProperty("onlyValid")      boolean onlyValid,
        @JsonProperty("lang")           String lang,
        @JsonProperty("clientData")     String clientData
) {}
