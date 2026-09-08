package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SchemaDeliveryCeilingTest {

    private static final String BOUND = "learcredential.employee.w3c.4";
    private static final String UNBOUND = "gx.labelcredential.w3c.2";

    @Mock
    private CredentialProfileCatalog credentialProfileCatalog;

    @InjectMocks
    private SchemaDeliveryCeiling ceiling;

    private static CredentialProfile bound(String configId) {
        return CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .format("jwt_vc_json")
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .proofTypesSupported(Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                        .proofSigningAlgValuesSupported(Set.of("ES256"))
                        .build()))
                .build();
    }

    private static CredentialProfile unbound(String configId) {
        return CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .format("jwt_vc_json")
                .build();
    }

    @Nested
    class ResolveEligibleModes {

        @Test
        void resolveEligibleModes_boundType_excludesDirect() {
            when(credentialProfileCatalog.getByConfigurationId(BOUND)).thenReturn(bound(BOUND));

            assertThat(ceiling.resolveEligibleModes(BOUND))
                    .containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI)
                    .doesNotContain(DeliveryMode.DIRECT);
        }

        @Test
        void resolveEligibleModes_unboundType_allowsEveryMode() {
            when(credentialProfileCatalog.getByConfigurationId(UNBOUND)).thenReturn(unbound(UNBOUND));

            assertThat(ceiling.resolveEligibleModes(UNBOUND))
                    .isEqualTo(EnumSet.allOf(DeliveryMode.class));
        }

        /**
         * The ceiling reads {@code proof_types_supported} and nothing else (ADR-110). A profile still
         * carrying {@code cnf_required} must not change the answer -- that field decided eligibility
         * before this Story and the whole point is that it no longer does.
         */
        @Test
        void resolveEligibleModes_unboundButCnfRequired_stillAllowsDirect() {
            CredentialProfile exempt = CredentialProfile.builder()
                    .credentialConfigurationId("learcredential.machine.w3c.3")
                    .format("jwt_vc_json")
                    .cnfRequired(true)
                    .build();
            when(credentialProfileCatalog.getByConfigurationId("learcredential.machine.w3c.3"))
                    .thenReturn(exempt);

            assertThat(ceiling.resolveEligibleModes("learcredential.machine.w3c.3"))
                    .contains(DeliveryMode.DIRECT);
        }

        @Test
        void resolveEligibleModes_unknownType_failsLoudlyRatherThanDefaultingOpen() {
            when(credentialProfileCatalog.getByConfigurationId("nope")).thenReturn(null);

            assertThatThrownBy(() -> ceiling.resolveEligibleModes("nope"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("nope");
        }
    }

    @Nested
    class ValidateWithinCeiling {

        @Test
        void validateWithinCeiling_walletModesOnBoundType_passes() {
            when(credentialProfileCatalog.getByConfigurationId(BOUND)).thenReturn(bound(BOUND));

            assertThatCode(() -> ceiling.validateWithinCeiling(BOUND, EnumSet.of(DeliveryMode.EMAIL)))
                    .doesNotThrowAnyException();
        }

        @Test
        void validateWithinCeiling_directOnBoundType_rejectsNamingModeTypeAndWhatRemains() {
            when(credentialProfileCatalog.getByConfigurationId(BOUND)).thenReturn(bound(BOUND));
            Set<DeliveryMode> direct = EnumSet.of(DeliveryMode.DIRECT);

            assertThatThrownBy(() -> ceiling.validateWithinCeiling(BOUND, direct))
                    .isInstanceOf(DeliveryModeNotEligibleException.class)
                    .hasMessageContaining("direct")
                    .hasMessageContaining(BOUND)
                    // A message that says only what is forbidden leaves the caller guessing (ES-03).
                    .hasMessageContaining("email,ui");
        }

        @Test
        void validateWithinCeiling_hybridContainingDirectOnBoundType_rejectsTheWholeRequest() {
            when(credentialProfileCatalog.getByConfigurationId(BOUND)).thenReturn(bound(BOUND));
            Set<DeliveryMode> hybrid = EnumSet.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL);

            assertThatThrownBy(() -> ceiling.validateWithinCeiling(BOUND, hybrid))
                    .isInstanceOf(DeliveryModeNotEligibleException.class);
        }

        @Test
        void validateWithinCeiling_directOnUnboundType_passes() {
            when(credentialProfileCatalog.getByConfigurationId(UNBOUND)).thenReturn(unbound(UNBOUND));

            assertThatCode(() -> ceiling.validateWithinCeiling(UNBOUND, EnumSet.of(DeliveryMode.DIRECT)))
                    .doesNotThrowAnyException();
        }
    }
}
