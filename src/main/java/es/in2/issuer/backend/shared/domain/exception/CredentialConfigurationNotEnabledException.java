package es.in2.issuer.backend.shared.domain.exception;

/**
 * Raised by {@code PATCH /api/v1/backoffice/credential-catalog} (AC-11) when a declared
 * {@code credential_configuration_id} exists in the global registry but is not currently
 * enabled for the tenant. Distinct from {@link UnknownCredentialConfigurationException}
 * (400, "does not exist in any registry") and {@link CredentialCatalogNotConfiguredException}
 * (404, "this tenant has no catalog at all"): here the type exists globally, it simply is
 * not enabled for this tenant -- maps to 409 (AD-13).
 */
public class CredentialConfigurationNotEnabledException extends RuntimeException {

    public CredentialConfigurationNotEnabledException(String message) {
        super(message);
    }

}
