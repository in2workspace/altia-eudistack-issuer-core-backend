package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.EnumSet;
import java.util.Set;

/**
 * The set of delivery modes a credential type's <em>schema</em> allows -- the ceiling that no tenant
 * configuration may exceed (ADR-110, EUD-168 AD-1).
 *
 * <p>Direct delivery has no wallet and therefore no OID4VCI proof-of-possession, so a type that
 * requires holder binding cannot genuinely be bound through it. Eligibility for {@code direct} is
 * consequently a property of the schema, not a tenant preference: before this, a tenant could enable
 * {@code direct} for a bound type and the contradiction only surfaced at issuance.
 *
 * <p>The distinction that matters is <em>ceiling</em> versus <em>default</em>. Tenant configuration
 * narrows what the schema permits; it never widens it. A stored configuration that predates this rule
 * and still lists {@code direct} for a bound type is intersected away rather than honoured.
 *
 * <p>Deliberately free of I/O: it reads the profile registry and nothing else, so it can be called
 * from the issuance path without adding a round trip, and tested without mocks beyond the registry.
 */
@Service
@RequiredArgsConstructor
public class SchemaDeliveryCeiling {

    private final CredentialProfileCatalog credentialProfileCatalog;

    /**
     * The modes this credential type's schema permits.
     *
     * <p>Bound types resolve to the wallet modes only; unbound types to every mode.
     *
     * @throws IllegalStateException if the type is unknown -- callers on the issuance path validate
     *         the {@code credential_configuration_id} earlier, so reaching here with an unknown one is
     *         a programming error, not a user error.
     */
    public Set<DeliveryMode> resolveEligibleModes(String credentialConfigurationId) {
        CredentialProfile profile = credentialProfileCatalog.getByConfigurationId(credentialConfigurationId);
        if (profile == null) {
            throw new IllegalStateException(
                    "Unknown credential_configuration_id reached the delivery ceiling: "
                            + credentialConfigurationId);
        }
        return profile.requiresHolderBinding()
                ? EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI)
                : EnumSet.allOf(DeliveryMode.class);
    }

    /**
     * @throws DeliveryModeNotEligibleException naming both the rejected mode and what remains
     *         available -- a message that says only what is forbidden leaves the caller guessing.
     */
    public void validateWithinCeiling(String credentialConfigurationId, Set<DeliveryMode> requestedModes) {
        Set<DeliveryMode> ceiling = resolveEligibleModes(credentialConfigurationId);
        for (DeliveryMode mode : requestedModes) {
            if (!ceiling.contains(mode)) {
                throw new DeliveryModeNotEligibleException(String.format(
                        "Delivery mode '%s' is not eligible for credential type '%s': its schema requires "
                                + "cryptographic holder binding. Eligible modes: %s",
                        mode.value, credentialConfigurationId, DeliveryMode.toCanonicalCsv(ceiling)));
            }
        }
    }

}
