package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;

/**
 * Lookup port for a credential type's schema profile, keyed by {@code credential_configuration_id}
 * (ADR-110, EUD-168 TD-11). The domain depends only on this interface;
 * {@code CredentialProfileRegistry} (infrastructure) is the sole implementation.
 */
public interface CredentialProfileCatalog {

    CredentialProfile getByConfigurationId(String credentialConfigurationId);
}
