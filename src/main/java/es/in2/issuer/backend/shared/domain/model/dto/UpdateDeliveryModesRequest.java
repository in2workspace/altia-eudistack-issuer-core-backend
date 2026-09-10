package es.in2.issuer.backend.shared.domain.model.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Map;
import java.util.Set;

/**
 * Write payload for {@code PATCH /api/v1/backoffice/credential-catalog} (AC-11). Unlike the
 * {@code PUT} sibling ({@link UpdateCredentialCatalogRequest}), this never enables or
 * disables a type: it touches only the delivery modes of the declared
 * {@code credential_configuration_id}s (AD-14).
 *
 * <p>Reuses, literally, the same container-element constraints as
 * {@code UpdateCredentialCatalogRequest#deliveryModesByConfigurationId} (security review
 * F4). The only difference: this field is {@code @NotEmpty} -- a PATCH with no entries is
 * a no-op and is rejected with 400, consistent with ES-02.
 */
public record UpdateDeliveryModesRequest(
        @NotEmpty(message = "deliveryModesByConfigurationId must not be empty")
        @Size(max = 32, message = "deliveryModesByConfigurationId must declare at most 32 credential configuration ids")
        Map<
                @Pattern(regexp = "^[a-zA-Z0-9._-]{1,128}$",
                        message = "credential_configuration_id key must be 1-128 characters, letters/digits/./_/- only")
                String,
                @NotNull(message = "delivery modes must not be null for a declared credential configuration id")
                @Size(min = 1, max = 3, message = "delivery modes must declare between 1 and 3 values")
                Set<@Size(max = 16, message = "delivery mode value too long") String>
        > deliveryModesByConfigurationId
) {}
