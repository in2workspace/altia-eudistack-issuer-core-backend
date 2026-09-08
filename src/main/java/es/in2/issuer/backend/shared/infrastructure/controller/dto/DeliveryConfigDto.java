package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DeliveryConfigDto(
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @JsonProperty("eligible_modes") List<String> eligibleModes,

        /**
         * The ceiling the schema imposes, echoed on reads so a TenantAdmin can see why a mode is
         * unavailable rather than discovering it through a rejected write (EUD-168 AC-11). Null on
         * requests -- it is derived, never supplied.
         */
        @JsonProperty("schema_eligible_modes") List<String> schemaEligibleModes
) {
}
