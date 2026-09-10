package es.in2.issuer.backend.shared.domain.model.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Map;
import java.util.Set;

/**
 * Write payload for {@code PUT /api/v1/backoffice/credential-catalog}. Replaces the full set
 * of credential configuration ids enabled for the current tenant, and optionally the
 * delivery modes configured per type.
 *
 * <p>A {@code null} or empty {@code enabledConfigurationIds} is rejected (400): an empty
 * catalog now means "nothing enabled" rather than the former "empty = all enabled"
 * invariant, so it can only be reached by mistake. A tenant that must stop issuing is
 * handled by disabling the tenant, not by emptying its catalog.
 *
 * <p>{@code deliveryModesByConfigurationId} is optional/nullable (EUD-169, additive
 * contract, AD-4): omitting it (or a {@code ccid} inside it) preserves that type's
 * currently-stored delivery modes rather than clearing them. Values are raw strings --
 * parsed into {@code DeliveryMode} at the controller boundary, not here.
 *
 * <p>Security review (F4): the map, its keys and its values are bounded -- an
 * unconstrained map previously let an attacker-controlled key (a
 * {@code credential_configuration_id} that is never validated against the registry before
 * being echoed into an error message) or a {@code null} value reach a log line / RFC-9457
 * {@code detail} unsanitized. The registry today holds ~7 profiles and a request declares
 * at most 3 delivery modes (direct/email/ui); the bounds below are generous, not tight.
 * {@code enabledConfigurationIds} carries the same bound (F4, second pass): it was left
 * unbounded when the sibling map was first fixed, reaching {@code UnknownCredentialConfigurationException}'s
 * message (and its log line) unsanitized the same way.
 */
public record UpdateCredentialCatalogRequest(
        @NotEmpty(message = "enabledConfigurationIds must not be empty")
        @Size(max = 64, message = "enabledConfigurationIds must declare at most 64 credential configuration ids")
        Set<
                @Pattern(regexp = "^[a-zA-Z0-9._-]{1,128}$",
                        message = "credential_configuration_id must be 1-128 characters, letters/digits/./_/- only")
                String
        > enabledConfigurationIds,

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
