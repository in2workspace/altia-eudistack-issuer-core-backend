package es.in2.issuer.backend.shared.domain.model.dto;

import jakarta.validation.constraints.NotEmpty;

import java.util.Map;
import java.util.Set;

/**
 * Write payload for {@code PUT /admin/v1/credential-catalog}. Replaces the full set
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
 */
public record UpdateCredentialCatalogRequest(
        @NotEmpty(message = "enabledConfigurationIds must not be empty")
        Set<String> enabledConfigurationIds,

        Map<String, Set<String>> deliveryModesByConfigurationId
) {}
