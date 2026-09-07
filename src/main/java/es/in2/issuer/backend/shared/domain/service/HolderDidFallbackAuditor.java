package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.util.DidKeyDerivation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Derives the holder {@code did:key} from a jwk-shaped {@code cnf} for the EUD-168 AD-8 exempt
 * credential types, auditing the case where {@link DidKeyDerivation#deriveDidKeyFromJwk} falls back
 * to a random {@code urn:uuid} instead of throwing (TD-09).
 *
 * <p>{@code null} is returned unless the derivation actually produced a {@code did:...} identifier:
 * binding a fabricated, unrelated identifier into {@code mandatee.id} would be worse than leaving it
 * unbound. D1/D2 canonicalize {@code holder_key} to fixed-length coordinates before either caller
 * below can reach this, so the fallback is unreachable in practice for a value that already passed
 * {@code HolderKey.validateAndCanonicalizeJwk} -- kept as a correlatable signal, distinguishable from
 * an operational {@code WARN}, in case a future Nimbus version or a second, unvalidated caller of
 * {@link DidKeyDerivation} changes that.
 *
 * <p>Shared between {@code IssuanceWorkflowImpl}'s direct leg and
 * {@code Oid4VciCredentialWorkflowImpl}'s wallet leg, which both apply the same guard for the same
 * AD-8 exemption.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HolderDidFallbackAuditor {

    private static final String AUDIT_EVENT_HOLDER_DID_DERIVATION_FALLBACK = "credential.holder_did.derivation_fallback";

    private final AuditService auditService;

    @SuppressWarnings("unchecked")
    public String deriveFromJwkCnf(String processId, String issuanceId, Map<String, Object> cnf) {
        Object jwk = cnf != null ? cnf.get("jwk") : null;
        if (!(jwk instanceof Map<?, ?> jwkMap)) {
            return null;
        }
        String holderDid = DidKeyDerivation.deriveDidKeyFromJwk((Map<String, Object>) jwkMap);
        if (holderDid.startsWith("did:")) {
            return holderDid;
        }
        auditFallback(processId, issuanceId);
        return null;
    }

    /** Best-effort (ES-03/ES-04): a broken audit channel must never fail an issuance that would otherwise succeed. */
    private void auditFallback(String processId, String issuanceId) {
        try {
            auditService.auditFailure(AUDIT_EVENT_HOLDER_DID_DERIVATION_FALLBACK, null,
                    "did_key_derivation_did_not_produce_a_did",
                    Map.of("processId", processId, "issuanceId", issuanceId));
        } catch (RuntimeException e) {
            log.warn("processId={} issuanceId={} action=deriveFromJwkCnf step=auditFailureFailed error={}",
                    processId, issuanceId, e.getMessage(), e);
        }
    }
}
