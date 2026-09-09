package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record IssuanceRequest(
        @NotBlank(message = "credential_configuration_id is required")
        @Size(max = 100, message = "credential_configuration_id must be at most 100 characters")
        @Pattern(regexp = "^[a-zA-Z0-9._-]*$", message = "credential_configuration_id must only contain letters, digits, dots, underscores and hyphens")
        @JsonAlias("schema")
        @JsonProperty(value = "credential_configuration_id", required = true) String credentialConfigurationId,
        @NotNull(message = "payload is required")
        @JsonProperty(value = "payload", required = true) JsonNode payload,
        // TD-06: bounded before it ever reaches DeliveryMode.parse or a log line -- the real values
        // ("direct"/"email"/"ui", CSV, up to 3 of them) never come close to 64 chars; the pattern
        // blocks CRLF/control-character injection (e.g. into IssuanceWorkflowImpl's log.error) without
        // hardcoding the enum values here, so DeliveryMode.parse stays the single source of truth for
        // which combinations are actually valid.
        @Size(max = 64, message = "delivery must be at most 64 characters")
        @Pattern(regexp = "^[a-zA-Z,\\s]*$", message = "delivery must only contain letters, commas and whitespace")
        @JsonProperty("delivery") String delivery,
        @NotBlank(message = "email is required")
        @Email(message = "email must be a well-formed email address")
        @Size(max = 254, message = "email must be at most 254 characters")
        @JsonProperty("email") String email,
        @Size(max = 64, message = "grant_type must be at most 64 characters")
        @Pattern(regexp = "^[a-zA-Z0-9_:-]*$", message = "grant_type must only contain letters, digits, underscore, colon and hyphen")
        @JsonProperty("grant_type") String grantType,
        @JsonProperty("holder_key") JsonNode holderKey
) {
    public IssuanceRequest(String credentialConfigurationId, JsonNode payload, String delivery,
                           String email, String grantType) {
        this(credentialConfigurationId, payload, delivery, email, grantType, null);
    }
}
