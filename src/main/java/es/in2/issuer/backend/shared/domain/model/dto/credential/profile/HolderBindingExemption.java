package es.in2.issuer.backend.shared.domain.model.dto.credential.profile;

import java.util.List;

/**
 * The closed list of credential types allowed to carry a {@code cnf} claim without declaring
 * {@code proof_types_supported} -- the scoped exception to ADR-110 (AD-8, EUD-168).
 *
 * <p>ADR-110 makes {@code proof_types_supported} the single signal of holder binding: present means
 * bound and ineligible for direct delivery, absent means unbound and eligible. It follows that an
 * unbound type has no channel through which a holder key could ever arrive, so it can carry no
 * {@code cnf}. For the machine LEARCredential that conclusion is premature: the machine does own a
 * key pair, it simply has no wallet with which to prove possession at the credential endpoint. The
 * business needs those types delivered directly <em>and</em> bound.
 *
 * <p>The types listed here therefore drop both OID4VCI binding fields -- so they stay eligible for
 * direct delivery, per ADR-110 -- while keeping {@code cnf_required: true}, and source their
 * {@code cnf} from the {@code holder_key} supplied in the issuance request body, for every delivery
 * mode rather than the direct one alone: with {@code proof_types_supported} gone no key proof
 * arrives through the wallet flow either, so the request is the only source of a holder key there is.
 *
 * <p>Deliberately hardcoded rather than a profile field. A field would be the alternative ADR-110
 * rejects -- a fourth signal free to contradict the published metadata -- and it would outlive its
 * reason. Two literals read as what they are: an exception with an expiry date.
 *
 * <p>Matched by <em>family prefix</em>, not by exact configuration id, so a version bump of either
 * machine credential does not need a code change to keep issuing. The looser match costs little:
 * the exemption only has an effect on a profile that declares {@code cnf_required} with no
 * {@code proof_types_supported}, and a future machine profile that recovers its key proof is not in
 * that state at all -- it simply stops needing the exemption. What the prefix does cost is a fuzzier
 * retirement: with exact ids, retiring meant deleting two known profiles, whereas a prefix silently
 * covers versions nobody has written yet.
 *
 * <h2>Retirement</h2>
 * When machines get a wallet of their own, these types recover {@code proof_types_supported}, stop
 * being eligible for direct delivery, and derive {@code cnf} from the key proof again. Retiring the
 * exception then means restoring both fields in every machine profile then in use and emptying this
 * list -- after which this class, its use in {@link CredentialProfileBindingInvariant}, the
 * holder-key branch in {@code IssuanceWorkflowImpl} and the whole persistence hop the wallet modes
 * need (the {@code holder_cnf} column, {@code HolderCnfJson}, and {@code resolveCnf}'s fallback in
 * {@code Oid4VciCredentialWorkflowImpl}) can all be deleted.
 *
 * <p><strong>Caveat.</strong> The {@code holder_key} arrives with no proof of possession, so the
 * resulting {@code cnf} is an issuer assertion, not cryptographic evidence (EUD-168 R-7).
 */
public final class HolderBindingExemption {

    private static final List<String> EXEMPT_CONFIGURATION_ID_PREFIXES = List.of(
            "learcredential.machine.sd.",
            "learcredential.machine.w3c."
    );

    private HolderBindingExemption() {
    }

    /**
     * {@code true} when this credential type sources its {@code cnf} from the issuance request
     * instead of from an OID4VCI key proof.
     */
    public static boolean isExempt(String credentialConfigurationId) {
        if (credentialConfigurationId == null) {
            return false;
        }
        return EXEMPT_CONFIGURATION_ID_PREFIXES.stream().anyMatch(credentialConfigurationId::startsWith);
    }

}
