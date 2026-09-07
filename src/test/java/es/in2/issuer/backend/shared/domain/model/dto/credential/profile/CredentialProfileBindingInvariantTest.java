package es.in2.issuer.backend.shared.domain.model.dto.credential.profile;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialProfileBindingInvariantTest {

    private static final Map<String, CredentialProfile.ProofTypeConfig> JWT_PROOF =
            Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                    .proofSigningAlgValuesSupported(Set.of("ES256"))
                    .build());

    private static CredentialProfile.CredentialProfileBuilder profile(String configId) {
        return CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .format("jwt_vc_json");
    }

    @Nested
    class Invariant1_TheTwoOid4vciFieldsTravelTogether {

        @Test
        void validate_bothPresent_passes() {
            assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                    profile("learcredential.employee.w3c.4")
                            .cryptographicBindingMethodsSupported(Set.of("did:key"))
                            .proofTypesSupported(JWT_PROOF)
                            .build()))
                    .doesNotThrowAnyException();
        }

        @Test
        void validate_bothAbsent_passes() {
            assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                    profile("gx.labelcredential.w3c.2").build()))
                    .doesNotThrowAnyException();
        }

        @Test
        void validate_bindingMethodsWithoutProofTypes_failsNamingProfileAndField() {
            CredentialProfile profile = profile("some.profile.1")
                    .cryptographicBindingMethodsSupported(Set.of("did:key"))
                    .build();

            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(profile))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("some.profile.1")
                    .hasMessageContaining("cryptographic_binding_methods_supported");
        }

        @Test
        void validate_proofTypesWithoutBindingMethods_failsNamingProfileAndField() {
            CredentialProfile profile = profile("some.profile.2")
                    .proofTypesSupported(JWT_PROOF)
                    .build();

            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(profile))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("some.profile.2")
                    .hasMessageContaining("proof_types_supported");
        }

        @Test
        void validate_bindingMethodsWithEmptyProofTypes_failsNamingProfileAndField() {
            CredentialProfile profile = profile("some.profile.4")
                    .cryptographicBindingMethodsSupported(Set.of("did:key"))
                    .proofTypesSupported(Map.of())
                    .build();

            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(profile))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("removing the key");
        }

        /**
         * EC-01. An empty object is not an absent field. Invariant 1 alone cannot catch the case where
         * both fields are emptied together -- it reads them as "agreeing" (both absent) -- so this check
         * must run unconditionally, independent of invariant 1's comparison.
         */
        @Test
        void validate_proofTypesSupportedPresentButEmpty_failsNamingProfileAndField() {
            CredentialProfile profile = profile("some.profile.5")
                    .proofTypesSupported(Map.of())
                    .build();

            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(profile))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("some.profile.5")
                    .hasMessageContaining("proof_types_supported")
                    .hasMessageContaining("removing the key");
        }

        @Test
        void validate_cryptographicBindingMethodsSupportedPresentButEmpty_failsNamingProfileAndField() {
            CredentialProfile profile = profile("some.profile.6")
                    .cryptographicBindingMethodsSupported(Set.of())
                    .build();

            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(profile))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("some.profile.6")
                    .hasMessageContaining("cryptographic_binding_methods_supported")
                    .hasMessageContaining("removing the key");
        }

        @Test
        void validate_bothFieldsPresentButEmptyTogether_stillFailsRatherThanReadingAsAbsence() {
            CredentialProfile profile = profile("some.profile.7")
                    .cryptographicBindingMethodsSupported(Set.of())
                    .proofTypesSupported(Map.of())
                    .build();

            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(profile))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("some.profile.7");
        }
    }

    @Nested
    class Invariant2_CnfRequiredNeedsAProofSource {

        @Test
        void validate_cnfRequiredWithProofTypes_passes() {
            assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                    profile("learcredential.employee.w3c.4")
                            .cryptographicBindingMethodsSupported(Set.of("did:key"))
                            .proofTypesSupported(JWT_PROOF)
                            .cnfRequired(true)
                            .build()))
                    .doesNotThrowAnyException();
        }

        @Test
        void validate_cnfRequiredWithoutProofTypesOnAnOrdinaryType_failsAtStartup() {
            CredentialProfile profile = profile("gx.labelcredential.w3c.2")
                    .cnfRequired(true)
                    .build();

            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(profile))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("gx.labelcredential.w3c.2")
                    .hasMessageContaining("cnf_required");
        }
    }

    /**
     * AD-8. The exemption is what lets the machine types keep a cnf sourced from the issuance request
     * while staying eligible for direct delivery. It must apply to those two ids and to nothing else --
     * an exemption that leaks is indistinguishable from having dropped the invariant.
     */
    @Nested
    class Ad8Exemption {

        @Test
        void validate_exemptTypesKeepCnfRequiredWithoutProofTypes_passes() {
            for (String configId : new String[]{"learcredential.machine.sd.1", "learcredential.machine.w3c.3"}) {
                assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                        profile(configId).cnfRequired(true).build()))
                        .as("exempt type %s must load", configId)
                        .doesNotThrowAnyException();
            }
        }

        /** The prefix match exists so a version bump does not need a code change to keep issuing. */
        @Test
        void validate_futureVersionsOfTheSameMachineFamilies_areCoveredWithoutACodeChange() {
            for (String configId : new String[]{"learcredential.machine.w3c.4", "learcredential.machine.sd.2"}) {
                assertThatCode(() -> CredentialProfileBindingInvariant.validate(
                        profile(configId).cnfRequired(true).build()))
                        .as("future machine version %s must load", configId)
                        .doesNotThrowAnyException();
            }
        }

        @Test
        void validate_aTypeOutsideTheMachineFamilies_stillFails() {
            // The exemption is scoped to the machine credential families and nothing else: any other
            // type in that same shape is the incoherence the invariant exists to catch.
            for (String configId : new String[]{
                    "learcredential.employee.w3c.4", "gx.labelcredential.w3c.2", "learcredential.machinery.w3c.1"}) {
                CredentialProfile profile = profile(configId).cnfRequired(true).build();

                assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(profile))
                        .as("non-exempt type %s must fail", configId)
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining(configId);
            }
        }

        @Test
        void validate_exemptTypeStillSubjectToInvariant1() {
            CredentialProfile profile = profile("learcredential.machine.sd.1")
                    .cryptographicBindingMethodsSupported(Set.of("did:key"))
                    .cnfRequired(true)
                    .build();

            assertThatThrownBy(() -> CredentialProfileBindingInvariant.validate(profile))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("cryptographic_binding_methods_supported");
        }
    }
}
