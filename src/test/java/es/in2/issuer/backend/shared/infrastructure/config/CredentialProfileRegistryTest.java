package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CredentialProfileRegistryTest {

    // Mirrors the application mapper (IssuerApiApplication): a profile may carry members the
    // model does not declare, and those must be dropped rather than fail startup.
    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    @Test
    void shouldLoadProfileAndLookupByConfigurationId() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile).isNotNull();
        assertThat(profile.format()).isEqualTo("jwt_vc_json");
        assertThat(profile.scope()).isEqualTo("lear_credential_employee");
        assertThat(profile.validityDays()).isEqualTo(365);
        assertThat(profile.issuerType()).isEqualTo(CredentialProfile.IssuerType.DETAILED);
        assertThat(profile.cnfRequired()).isTrue();
    }

    @Test
    void shouldLookupByCredentialType() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByCredentialType("learcredential.employee.w3c.4");
        assertThat(profile).isNotNull();
        assertThat(profile.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
    }

    @Test
    void shouldReturnNullForUnknownKeys() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getByConfigurationId("NonExistent")).isNull();
        assertThat(registry.getByCredentialType("NonExistent")).isNull();
    }

    @Test
    void shouldLoadMultipleProfiles() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile(), validMachineProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getAllProfiles()).hasSize(2);
        assertThat(registry.getByConfigurationId("learcredential.employee.w3c.4")).isNotNull();
        assertThat(registry.getByConfigurationId("learcredential.machine.w3c.3")).isNotNull();
    }

    @Test
    void shouldDeriveCredentialTypeFromDefinition() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile.credentialType()).isEqualTo("learcredential.employee.w3c.4");
        assertThat(profile.credentialDefinition().type())
                .containsExactly("VerifiableCredential", "learcredential.employee.w3c.4");
    }

    @Test
    void shouldParseCredentialMetadata() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile.credentialMetadata()).isNotNull();
        assertThat(profile.credentialMetadata().display()).hasSize(1);
        assertThat(profile.credentialMetadata().display().getFirst().name()).isEqualTo("LEAR Credential Employee");
        assertThat(profile.credentialMetadata().claims()).hasSize(5);
    }

    @Test
    void shouldParseEveryDisplayMemberTheSpecDefines() throws IOException {
        // The credential display object is name + locale + description + logo +
        // background_color + background_image + text_color (OID4VCI 1.0 Final section
        // 12.2.4). A member the model does not declare is dropped on parse and never
        // reaches the published metadata — which is how the card colours went missing.
        String displayProfileJson = """
                {
                  "credential_configuration_id": "learcredential.employee.w3c.4",
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "learcredential.employee.w3c.4"]
                  },
                  "credential_metadata": {
                    "display": [{
                      "name": "LEAR Credential Employee",
                      "locale": "en",
                      "description": "Verifiable Credential for employees",
                      "logo": { "uri": "https://issuer.example.com/logo.svg", "alt_text": "Issuer" },
                      "background_color": "#1B2A41",
                      "background_image": { "uri": "https://issuer.example.com/bg.svg" },
                      "text_color": "#FFFFFF"
                    }]
                  }
                }
                """;
        ResourcePatternResolver resolver = mockResolver(namedResource("display.json", displayProfileJson));

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile.DisplayInfo display =
                registry.getByConfigurationId("learcredential.employee.w3c.4").credentialMetadata().display().getFirst();
        assertThat(display.name()).isEqualTo("LEAR Credential Employee");
        assertThat(display.description()).isEqualTo("Verifiable Credential for employees");
        assertThat(display.backgroundColor()).isEqualTo("#1B2A41");
        assertThat(display.textColor()).isEqualTo("#FFFFFF");
        assertThat(display.logo().uri()).isEqualTo("https://issuer.example.com/logo.svg");
        assertThat(display.logo().altText()).isEqualTo("Issuer");
        assertThat(display.backgroundImage().uri()).isEqualTo("https://issuer.example.com/bg.svg");
        assertThat(display.backgroundImage().altText()).isNull();
    }

    @Test
    void shouldIgnoreUnknownClaimMembers() throws IOException {
        String labelProfileJson = """
                {
                  "credential_configuration_id": "gx.labelcredential.w3c.2",
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "gx.labelcredential.w3c.2"]
                  },
                  "credential_metadata": {
                    "display": [{"name": "Gaia-X Label Credential", "locale": "en"}],
                    "claims": [
                      {
                        "path": ["credentialSubject", "gx:labelLevel"],
                        "display": [{"name": "Label Level", "locale": "en"}],
                        "value_map": {"BL": "Baseline", "P": "Professional", "P+": "Professional Plus"}
                      },
                      {
                        "path": ["credentialSubject", "gx:engineVersion"],
                        "display": [{"name": "Engine Version", "locale": "en"}]
                      }
                    ]
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cryptographic_binding_methods_supported": ["did:key"],
                  "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                  },
                  "cnf_required": true
                }
                """;
        ResourcePatternResolver resolver = mockResolver(namedResource("gx-label-credential.json", labelProfileJson));

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        // A claims description object is path + display + mandatory (OID4VCI 1.0 Final
        // Appendix B.1). Anything else a profile carries — here the legacy `value_map` —
        // must stay out of the model, and therefore out of the published metadata.
        CredentialProfile profile = registry.getByConfigurationId("gx.labelcredential.w3c.2");
        assertThat(profile).isNotNull();
        assertThat(profile.credentialMetadata().claims()).hasSize(2);

        CredentialProfile.ClaimDefinition labelLevelClaim = profile.credentialMetadata().claims().getFirst();
        assertThat(labelLevelClaim.path()).containsExactly("credentialSubject", "gx:labelLevel");
        assertThat(labelLevelClaim.display()).hasSize(1);
    }

    @Test
    void shouldParseSubjectExtraction() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile.subjectExtraction()).isNotNull();
        assertThat(profile.subjectExtraction().strategy()).isEqualTo("concat");
        assertThat(profile.subjectExtraction().fields())
                .containsExactly("mandate.mandatee.firstName", "mandate.mandatee.lastName");
        assertThat(profile.subjectExtraction().separator()).isEqualTo(" ");
    }

    @Test
    void shouldParseOrganizationExtraction() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile.organizationExtraction()).isNotNull();
        assertThat(profile.organizationExtraction().strategy()).isEqualTo("field");
        assertThat(profile.organizationExtraction().field()).isEqualTo("mandate.mandator.organizationIdentifier");
    }

    @Test
    void shouldFailOnMissingConfigurationId() throws IOException {
        String json = """
                {
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "Test"]
                  }
                }
                """;
        ResourcePatternResolver resolver = mockResolver(namedResource("bad.json", json));

        assertThatThrownBy(() -> new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no credential_configuration_id");
    }

    @Test
    void shouldFailOnDuplicateConfigurationId() throws IOException {
        ResourcePatternResolver resolver = mockResolver(
                validEmployeeProfile(),
                namedResource("duplicate.json", validEmployeeProfileJson()));

        assertThatThrownBy(() -> new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate credential_configuration_id");
    }

    @Test
    void shouldKeepFirstProfileForDuplicateCredentialType() throws IOException {
        String duplicateTypeJson = """
                {
                  "credential_configuration_id": "DifferentId",
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "learcredential.employee.w3c.4"]
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cryptographic_binding_methods_supported": ["did:key"],
                  "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                  },
                  "cnf_required": true
                }
                """;
        ResourcePatternResolver resolver = mockResolver(
                validEmployeeProfile(),
                namedResource("dup-type.json", duplicateTypeJson));

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getAllProfiles()).hasSize(2);
        CredentialProfile typeResult = registry.getByCredentialType("learcredential.employee.w3c.4");
        assertThat(typeResult).isNotNull();
        assertThat(typeResult.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
    }

    @Test
    void shouldResolveProfileByConfigurationId() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.resolveProfile("learcredential.employee.w3c.4");
        assertThat(profile).isNotNull();
        assertThat(profile.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.4");
    }

    @Test
    void shouldResolveProfileByLegacyCredentialTypeName() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile(), legacyEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getByConfigurationId("LEARCredentialEmployee")).isNull();
        CredentialProfile profile = registry.resolveProfile("LEARCredentialEmployee");
        assertThat(profile).isNotNull();
        assertThat(profile.credentialConfigurationId()).isEqualTo("learcredential.employee.w3c.3");
    }

    @Test
    void shouldReturnNullWhenResolvingUnknownIdentifier() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.resolveProfile("NonExistent")).isNull();
    }

    @Test
    void shouldHandleEmptyResourceList() throws IOException {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        when(resolver.getResources(anyString())).thenReturn(new Resource[0]);

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getAllProfiles()).isEmpty();
    }

    @Test
    void shouldReturnUnmodifiableMap() throws IOException {
        ResourcePatternResolver resolver = mockResolver(validEmployeeProfile());

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");
        Map<String, CredentialProfile> allProfiles = registry.getAllProfiles();

        assertThatThrownBy(() -> allProfiles.put("key", null))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void shouldMergeProfileOverlayOntoCoreSchema() throws IOException {
        String coreJson = """
                {
                  "credential_configuration_id": "learcredential.employee.w3c.4",
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "learcredential.employee.w3c.4"]
                  },
                  "validity_days": 180,
                  "issuer_type": "DETAILED",
                  "cnf_required": false
                }
                """;
        String profileJson = """
                {
                  "credential_configuration_id": "learcredential.employee.w3c.4",
                  "validity_days": 365,
                  "cryptographic_binding_methods_supported": ["did:key"],
                  "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                  },
                  "cnf_required": true,
                  "scope": "lear_credential_employee"
                }
                """;
        ResourcePatternResolver resolver = mockResolver(
                namedResource("lear-credential-employee.json", coreJson),
                namedResource("lear-credential-employee.profile.json", profileJson));

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile).isNotNull();
        assertThat(profile.format()).isEqualTo("jwt_vc_json");
        assertThat(profile.validityDays()).isEqualTo(365);
        assertThat(profile.cnfRequired()).isTrue();
        assertThat(profile.scope()).isEqualTo("lear_credential_employee");
    }

    @Test
    void shouldUseCoreAsIsWhenNoProfileOverlayExists() throws IOException {
        String coreJson = """
                {
                  "credential_configuration_id": "learcredential.employee.w3c.4",
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "learcredential.employee.w3c.4"]
                  },
                  "validity_days": 180,
                  "issuer_type": "DETAILED",
                  "cnf_required": false
                }
                """;
        ResourcePatternResolver resolver = mockResolver(
                namedResource("lear-credential-employee.json", coreJson));

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile).isNotNull();
        assertThat(profile.validityDays()).isEqualTo(180);
        assertThat(profile.cnfRequired()).isFalse();
    }

    @Test
    void shouldNotTreatProfileFileAsCoreDuringLoading() throws IOException {
        String profileJson = """
                {
                  "credential_configuration_id": "orphan.profile",
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "orphan.profile"]
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cryptographic_binding_methods_supported": ["did:key"],
                  "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                  },
                  "cnf_required": true
                }
                """;
        ResourcePatternResolver resolver = mockResolver(
                namedResource("orphan.profile.json", profileJson));

        CredentialProfileRegistry registry = new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles");

        assertThat(registry.getAllProfiles()).isEmpty();
    }

    @Test
    void shouldFailWhenProfileOverlayHasNoConfigurationId() throws IOException {
        String coreJson = """
                {
                  "credential_configuration_id": "some.core",
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {
                    "type": ["VerifiableCredential", "some.core"]
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cryptographic_binding_methods_supported": ["did:key"],
                  "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                  },
                  "cnf_required": true
                }
                """;
        String badProfileJson = """
                {
                  "validity_days": 999
                }
                """;
        ResourcePatternResolver resolver = mockResolver(
                namedResource("some-core.json", coreJson),
                namedResource("bad-overlay.profile.json", badProfileJson));

        assertThatThrownBy(() -> new CredentialProfileRegistry(OBJECT_MAPPER, resolver, "classpath:credentials/profiles"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no credential_configuration_id");
    }

    // --- Helper methods ---

    private ResourcePatternResolver mockResolver(Resource... resources) throws IOException {
        ResourcePatternResolver resolver = mock(ResourcePatternResolver.class);
        when(resolver.getResources(anyString())).thenReturn(resources);
        return resolver;
    }

    private Resource validEmployeeProfile() {
        return namedResource("lear-credential-employee.json", validEmployeeProfileJson());
    }

    private Resource validMachineProfile() {
        return namedResource("lear-credential-machine.json", """
                {
                  "credential_configuration_id": "learcredential.machine.w3c.3",
                  "credential_format": "jwt_vc_json",
                  "scope": "lear_credential_machine",
                  "credential_definition": {
                    "context": ["https://www.w3.org/ns/credentials/v2"],
                    "type": ["VerifiableCredential", "learcredential.machine.w3c.3"]
                  },
                  "credential_metadata": {
                    "display": [{"name": "LEAR Credential Machine", "locale": "en"}],
                    "claims": []
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cryptographic_binding_methods_supported": ["did:key"],
                  "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                  },
                  "cnf_required": true,
                  "subject_extraction": {
                    "strategy": "field",
                    "fields": ["mandate.mandatee.domain"]
                  },
                  "organization_extraction": {
                    "strategy": "field",
                    "field": "mandate.mandator.organizationIdentifier"
                  }
                }
                """);
    }

    private Resource legacyEmployeeProfile() {
        return namedResource("lear-credential-employee-legacy.json", """
                {
                  "credential_configuration_id": "learcredential.employee.w3c.3",
                  "credential_format": "jwt_vc_json",
                  "scope": "lear_credential_employee",
                  "credential_definition": {
                    "context": [
                      "https://www.w3.org/ns/credentials/v2",
                      "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3"
                    ],
                    "type": ["VerifiableCredential", "LEARCredentialEmployee"]
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cryptographic_binding_methods_supported": ["did:key"],
                  "proof_types_supported": {
                    "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                  },
                  "cnf_required": true,
                  "policy_extraction": {
                    "powers_path": "credentialSubject.mandate.power",
                    "mandator_path": "credentialSubject.mandate.mandator",
                    "org_id_field": "organizationIdentifier"
                  }
                }
                """);
    }

    private String validEmployeeProfileJson() {
        return """
                {
                  "credential_configuration_id": "learcredential.employee.w3c.4",
                  "credential_format": "jwt_vc_json",
                  "scope": "lear_credential_employee",
                  "credential_definition": {
                    "context": [
                      "https://www.w3.org/ns/credentials/v2",
                      "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3"
                    ],
                    "type": ["VerifiableCredential", "learcredential.employee.w3c.4"]
                  },
                  "cryptographic_binding_methods_supported": ["did:key"],
                  "credential_signing_alg_values_supported": ["ES256"],
                  "proof_types_supported": {
                    "jwt": { "proof_signing_alg_values_supported": ["ES256"] }
                  },
                  "credential_metadata": {
                    "display": [{
                      "name": "LEAR Credential Employee",
                      "locale": "en",
                      "description": "Verifiable Credential for employees of an organization"
                    }],
                    "claims": [
                      { "path": ["credentialSubject", "mandate", "mandatee", "firstName"], "display": [{"name": "First Name", "locale": "en"}] },
                      { "path": ["credentialSubject", "mandate", "mandatee", "lastName"], "display": [{"name": "Last Name", "locale": "en"}] },
                      { "path": ["credentialSubject", "mandate", "mandatee", "email"], "display": [{"name": "Email", "locale": "en"}] },
                      { "path": ["credentialSubject", "mandate", "mandator", "organizationIdentifier"], "display": [{"name": "Organization", "locale": "en"}] },
                      { "path": ["credentialSubject", "mandate", "power"], "display": [{"name": "Powers", "locale": "en"}] }
                    ]
                  },
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cnf_required": true,
                  "description": "Verifiable Credential for employees of an organization",
                  "subject_extraction": {
                    "strategy": "concat",
                    "fields": ["mandate.mandatee.firstName", "mandate.mandatee.lastName"],
                    "separator": " "
                  },
                  "organization_extraction": {
                    "strategy": "field",
                    "field": "mandate.mandator.organizationIdentifier"
                  }
                }
                """;
    }

    private Resource namedResource(String filename, String content) {
        return new ByteArrayResource(content.getBytes(StandardCharsets.UTF_8)) {
            @Override
            public String getFilename() {
                return filename;
            }
        };
    }

    // --- EUD-168: fail-fast on incoherent profiles (AC-08) and the AD-8 exemption (AC-14) ---

    private static String profileJson(String configId, String bindingFields, boolean cnfRequired) {
        return """
                {
                  "credential_configuration_id": "%s",
                  "credential_format": "jwt_vc_json",
                  "credential_definition": {"type": ["VerifiableCredential", "%s"]},
                  %s
                  "validity_days": 365,
                  "issuer_type": "DETAILED",
                  "cnf_required": %s
                }
                """.formatted(configId, configId, bindingFields, cnfRequired);
    }

    private static final String BOTH_BINDING_FIELDS = """
              "cryptographic_binding_methods_supported": ["did:key"],
                  "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
            """;

    private CredentialProfileRegistry load(String filename, String json) throws java.io.IOException {
        return new CredentialProfileRegistry(
                OBJECT_MAPPER, mockResolver(namedResource(filename, json)), "classpath:credentials/profiles");
    }

    @Test
    void startupShouldFailWhenProfileDeclaresBindingMethodsWithoutProofTypes() {
        String json = profileJson("some.profile.1",
                "\"cryptographic_binding_methods_supported\": [\"did:key\"],", false);

        assertThatThrownBy(() -> load("incoherent.json", json))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("some.profile.1")
                .hasMessageContaining("cryptographic_binding_methods_supported");
    }

    @Test
    void startupShouldFailWhenNonExemptProfileDeclaresCnfRequiredWithoutProofTypes() {
        String json = profileJson("some.profile.2", "", true);

        assertThatThrownBy(() -> load("incoherent-cnf.json", json))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("some.profile.2")
                .hasMessageContaining("cnf_required");
    }

    @Test
    void startupShouldSucceedForTheAd8ExemptMachineProfiles() throws java.io.IOException {
        for (String configId : new String[]{"learcredential.machine.sd.1", "learcredential.machine.w3c.3"}) {
            CredentialProfileRegistry registry = load(configId + ".json", profileJson(configId, "", true));
            CredentialProfile profile = registry.getByConfigurationId(configId);
            assertThat(profile).isNotNull();
            assertThat(profile.cnfRequired()).isTrue();
            // Unbound by ADR-110 despite carrying cnf_required: that is what keeps direct delivery open.
            assertThat(profile.requiresHolderBinding()).isFalse();
        }
    }

    @Test
    void startupShouldSucceedForACoherentBoundProfile() throws java.io.IOException {
        CredentialProfileRegistry registry = load("bound.json",
                profileJson("learcredential.employee.w3c.4", BOTH_BINDING_FIELDS, true));

        CredentialProfile profile = registry.getByConfigurationId("learcredential.employee.w3c.4");
        assertThat(profile).isNotNull();
        assertThat(profile.requiresHolderBinding()).isTrue();
    }

    /**
     * TD-07 / EC-07: the other tests in this file load handcrafted fixtures through a mocked
     * {@link ResourcePatternResolver}. This one instead points a real
     * {@link PathMatchingResourcePatternResolver} at the actual vendored copy
     * ({@code dev-tools/credentials/profiles}, not the single fixture on the test classpath) to prove
     * the 13 real profiles -- 7 current plus 6 under {@code legacy/} -- load without violating
     * {@code CredentialProfileBindingInvariant}, exactly as they must at container startup.
     */
    @Test
    void shouldLoadTheThirteenRealVendoredProfilesWithoutViolatingTheInvariant() {
        ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();

        CredentialProfileRegistry registry = new CredentialProfileRegistry(
                OBJECT_MAPPER, resolver, "file:dev-tools/credentials/profiles");

        Set<String> currentConfigIds = Set.of(
                "doctorid.sd.1",
                "eu.europa.ec.eudi.pid.1",
                "gx.labelcredential.w3c.2",
                "learcredential.employee.sd.1",
                "learcredential.employee.w3c.4",
                "learcredential.machine.sd.1",
                "learcredential.machine.w3c.3");
        Set<String> legacyConfigIds = Set.of(
                "gx.labelcredential.w3c.1",
                "learcredential.employee.w3c.1",
                "learcredential.employee.w3c.2",
                "learcredential.employee.w3c.3",
                "learcredential.machine.w3c.1",
                "learcredential.machine.w3c.2");

        assertThat(registry.getAllProfiles()).hasSize(currentConfigIds.size() + legacyConfigIds.size());

        for (String configId : currentConfigIds) {
            assertThat(registry.getByConfigurationId(configId))
                    .as("current profile '%s' should have loaded", configId)
                    .isNotNull();
        }
        for (String configId : legacyConfigIds) {
            assertThat(registry.getByConfigurationId(configId))
                    .as("legacy profile '%s' should have loaded", configId)
                    .isNotNull();
        }
    }
}
