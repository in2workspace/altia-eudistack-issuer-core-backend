package es.in2.issuer.backend.shared.domain.model.dto;

import java.util.List;

/**
 * One entry of the tenant credential catalog: a globally-defined credential
 * configuration plus whether it is enabled for the current tenant.
 *
 * @param credentialConfigurationId id from {@code CredentialProfileRegistry}
 * @param displayName               human-readable name (first display entry, no i18n yet)
 * @param enabled                   true only if this id is explicitly enabled for the
 *                                  current tenant; a tenant with no stored config has
 *                                  every entry disabled
 * @param deliveryModes             modes actually eligible for this tenant+type: the
 *                                  stored configuration intersected with the schema
 *                                  ceiling, or the ceiling itself if nothing is stored
 *                                  (EUD-169, AC-01)
 * @param schemaEligibleModes       the schema-derived ceiling on its own, without the
 *                                  tenant's stored configuration intersected in (EUD-168
 *                                  {@code schema_eligible_modes} contract, AD-11)
 */
public record CredentialCatalogEntryDto(
        String credentialConfigurationId,
        String displayName,
        boolean enabled,
        List<String> deliveryModes,
        List<String> schemaEligibleModes
) {}
