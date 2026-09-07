package es.in2.issuer.backend.shared.domain.model.dto.credential.profile;

/**
 * Validates that a profile's three binding-related fields agree with one another, at profile-load
 * time rather than at issuance time (ADR-110, EUD-168 AD-4).
 *
 * <p>Three fields describe holder binding -- {@code proof_types_supported},
 * {@code cryptographic_binding_methods_supported} and the proprietary {@code cnf_required} -- and
 * nothing used to force them to agree. A profile could announce to wallets that they must send a key
 * proof while telling the issuer not to write {@code cnf}, and the contradiction stayed invisible
 * until the first failed issuance. Checking here turns that into a startup failure naming the profile
 * and the offending field: fail-fast at the loading boundary, not fail-late in production.
 */
public final class CredentialProfileBindingInvariant {

    private CredentialProfileBindingInvariant() {
    }

    /**
     * @throws IllegalStateException if the profile violates either invariant, naming the
     *         {@code credential_configuration_id} and the field in conflict.
     */
    public static void validate(CredentialProfile profile) {
        String configId = profile.credentialConfigurationId();
        boolean bound = profile.requiresHolderBinding();
        boolean declaresBindingMethods = profile.cryptographicBindingMethodsSupported() != null
                && !profile.cryptographicBindingMethodsSupported().isEmpty();

        // Invariant 1 -- no exceptions. The two OID4VCI fields travel together or not at all.
        if (declaresBindingMethods != bound) {
            throw new IllegalStateException(String.format(
                    "Incoherent credential profile '%s': 'cryptographic_binding_methods_supported' is %s "
                            + "while 'proof_types_supported' is %s. Both must be present and non-empty, "
                            + "or both absent. Declare absence by removing the key, not by emptying it.",
                    configId,
                    declaresBindingMethods ? "present and non-empty" : "absent or empty",
                    bound ? "present and non-empty" : "absent or empty"));
        }

        // EC-01 -- unconditional, independent of invariant 1: a key present but emptied is not the
        // same as a key that was never declared, and must not be read as absence. Invariant 1 alone
        // cannot catch this: when both fields are emptied together it sees them as agreeing (both
        // "absent"), which is exactly the false negative EC-01 exists to close.
        if (profile.proofTypesSupported() != null && profile.proofTypesSupported().isEmpty()) {
            throw new IllegalStateException(String.format(
                    "Incoherent credential profile '%s': 'proof_types_supported' is present but empty. "
                            + "An empty object is not the same as an absent field -- declare absence by "
                            + "removing the key, not by emptying it.",
                    configId));
        }
        if (profile.cryptographicBindingMethodsSupported() != null
                && profile.cryptographicBindingMethodsSupported().isEmpty()) {
            throw new IllegalStateException(String.format(
                    "Incoherent credential profile '%s': 'cryptographic_binding_methods_supported' is "
                            + "present but empty. An empty object is not the same as an absent field -- "
                            + "declare absence by removing the key, not by emptying it.",
                    configId));
        }

        // Invariant 2 -- exempted for the closed list of AD-8, and only for it. Those types keep
        // cnf_required: true with no proof_types_supported on purpose: their cnf comes from the
        // holder_key in the issuance request, not from a key proof.
        if (profile.cnfRequired() && !bound && !HolderBindingExemption.isExempt(configId)) {
            throw new IllegalStateException(String.format(
                    "Incoherent credential profile '%s': 'cnf_required' is true but "
                            + "'proof_types_supported' is absent or empty, so no holder key can ever "
                            + "reach the issuer and the cnf claim cannot be built. Either declare "
                            + "'proof_types_supported' or remove 'cnf_required'.",
                    configId));
        }
    }

}
