package es.in2.issuer.backend.shared.domain.model.dto;

import es.in2.issuer.backend.shared.domain.model.enums.UserRole;

/**
 * Encapsulates the authorization context resolved from the access token.
 *
 * @param organizationIdentifier the mandator's organization ID from the token
 * @param role                   the resolved user role ({@link UserRole})
 * @param readOnly               true when the user is a SysAdmin operating from the
 *                               {@code platform} tenant (cross-tenant read-only view)
 * @param tenantType             the type of the current tenant
 */
public record AuthorizationContext(
        String organizationIdentifier,
        UserRole role,
        boolean readOnly,
        String tenantType
) {
    public boolean isSysAdmin() {
        return role == UserRole.SYSADMIN;
    }

    public boolean isTenantAdmin() {
        return role == UserRole.TENANT_ADMIN || isSysAdmin();
    }

    public boolean canWrite() {
        return !readOnly;
    }

    /**
     * Whether the caller may read the tenant's credential catalog (EUD-169, AD-16):
     * a tenant administrator, SysAdmin (including its cross-tenant read-only view over
     * {@code platform}), and the tenant's operator ({@link UserRole#LEAR}) -- who needs
     * to discover a type's eligible delivery modes and schema ceiling before attempting
     * to issue it (AC-09, AC-12).
     *
     * <p>Deliberately does not delegate to {@link #isTenantAdmin()}: that predicate also
     * gates the write path ({@code CredentialCatalogController}'s write authorization),
     * and widening it would silently open {@code PUT}/{@code PATCH} to the operator too.
     *
     * <p>{@link UserRole} has exactly three values today, so this condition is vacuously
     * true for every role -- documented in {@code technical-design.md} §3.3.2, not a bug.
     * It stays an explicit role check rather than collapsing to "authenticated": a fourth
     * {@code UserRole} (auditor, holder, a service account, ...) must force a conscious
     * decision about whether it can read the catalog, not inherit access by omission. The
     * {@code UserRole} exhaustiveness test in {@code CredentialCatalogControllerTest} goes
     * red the day a fourth value is added -- that is the intended trigger for that decision.
     */
    public boolean canReadCredentialCatalog() {
        return isTenantAdmin() || role == UserRole.LEAR;
    }
}
