package es.in2.issuer.backend.shared.domain.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Extracted from {@code IssuanceWorkflowImplTest}/{@code Oid4VciCredentialWorkflowImplTest}'s
 * TD-09 tests when {@code holderDidFromCnf}/{@code resolveHolderDid}'s shared tail moved here --
 * both workflows now delegate to this class instead of duplicating the guard.
 */
@ExtendWith(MockitoExtension.class)
class HolderDidFallbackAuditorTest {

    @Mock
    private AuditService auditService;

    @InjectMocks
    private HolderDidFallbackAuditor holderDidFallbackAuditor;

    @Test
    void deriveFromJwkCnf_withNoJwk_returnsNullWithoutAuditing() {
        String result = holderDidFallbackAuditor.deriveFromJwkCnf("p", "issuance-1", Map.of());

        assertThat(result).isNull();
        verifyNoInteractions(auditService);
    }

    @Test
    void deriveFromJwkCnf_withValidJwk_returnsDidKeyWithoutAuditing() {
        Map<String, Object> jwk = Map.of("kty", "EC", "crv", "P-256",
                "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y", "4Etl4P43ISPjmk04lg9lNRq5-8gZ0uP1JYtiv0m6-oI");
        Map<String, Object> cnf = Map.of("jwk", jwk);

        String result = holderDidFallbackAuditor.deriveFromJwkCnf("p", "issuance-1", cnf);

        assertThat(result).startsWith("did:key:z");
        verifyNoInteractions(auditService);
    }

    /**
     * TD-09 (code-review re-verification, 2026-09-01). {@code DidKeyDerivation} is the last place a
     * decode-failure fallback (a random {@code urn:uuid}, never a {@code did:...}) could otherwise be
     * bound into {@code mandatee.id} unchallenged (F2a/B1) -- D1/D2 already close every path that
     * could reach it through either workflow's public API, since {@code HolderKey
     * .validateAndCanonicalizeJwk} rejects a non-decodable {@code x}/{@code y} before a request-level
     * {@code cnf} ever gets built. The fallback is forced here directly with a {@code cnf}
     * {@code HolderKey} would never have produced. Asserts it both still skips the binding (unchanged
     * behaviour) and emits the TD-09 audit signal, correlatable by {@code processId}/{@code
     * issuanceId} -- instead of leaving the case in {@code DidKeyDerivation}'s own {@code log.warn}
     * alone.
     */
    @SuppressWarnings("unchecked")
    @Test
    void deriveFromJwkCnf_derivationFallback_shouldAuditAndReturnNull() {
        Map<String, Object> jwk = Map.of("kty", "EC", "crv", "P-256", "x", "!!!not-base64url!!!", "y", "y-coord");
        Map<String, Object> cnf = Map.of("jwk", jwk);

        String result = holderDidFallbackAuditor.deriveFromJwkCnf("p", "issuance-1", cnf);

        assertThat(result).isNull();

        ArgumentCaptor<Map<String, Object>> detailsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditFailure(eq("credential.holder_did.derivation_fallback"), isNull(),
                anyString(), detailsCaptor.capture());
        assertThat(detailsCaptor.getValue())
                .containsEntry("processId", "p")
                .containsEntry("issuanceId", "issuance-1");
    }

    /** Best-effort (ES-03/ES-04): a broken audit channel must never fail an issuance that would otherwise succeed. */
    @Test
    void deriveFromJwkCnf_whenAuditChannelThrows_stillReturnsNull() {
        Map<String, Object> jwk = Map.of("kty", "EC", "crv", "P-256", "x", "!!!not-base64url!!!", "y", "y-coord");
        Map<String, Object> cnf = Map.of("jwk", jwk);
        doThrow(new RuntimeException("AUDIT channel down"))
                .when(auditService).auditFailure(anyString(), isNull(), anyString(), anyMap());

        String result = holderDidFallbackAuditor.deriveFromJwkCnf("p", "issuance-1", cnf);

        assertThat(result).isNull();
        verify(auditService, never()).auditSuccess(anyString(), anyString(), anyString(), anyString(), anyMap());
    }
}
