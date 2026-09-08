package es.in2.issuer.backend.shared.domain.model.dto.credential.profile;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialProfile(
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @JsonProperty("credential_format") String format,
        @JsonProperty("scope") String scope,
        @JsonProperty("credential_definition") CredentialDefinition credentialDefinition,
        @JsonProperty("cryptographic_binding_methods_supported") Set<String> cryptographicBindingMethodsSupported,
        @JsonProperty("credential_signing_alg_values_supported") Set<String> credentialSigningAlgValuesSupported,
        @JsonProperty("proof_types_supported") Map<String, ProofTypeConfig> proofTypesSupported,
        @JsonProperty("credential_metadata") CredentialMetadata credentialMetadata,
        @JsonProperty("validity_days") int validityDays,
        @JsonProperty("issuer_type") IssuerType issuerType,
        @JsonProperty("cnf_required") boolean cnfRequired,
        @JsonProperty("description") String description,
        @JsonProperty("subject_extraction") SubjectExtraction subjectExtraction,
        @JsonProperty("organization_extraction") OrganizationExtraction organizationExtraction,
        @JsonProperty("sd_jwt") SdJwtConfig sdJwt,
        @JsonProperty("credential_subject_strategy") String credentialSubjectStrategy,
        @JsonProperty("json_schema") String jsonSchema,
        @JsonProperty("policy_extraction") PolicyExtraction policyExtraction,
        @JsonProperty("issuance_policy") IssuancePolicy issuancePolicy,
        @JsonProperty("token_claims_mapping") TokenClaimsMapping tokenClaimsMapping,
        @JsonProperty("validation") Validation validation
) {

    @Builder
    public record CredentialDefinition(
            @JsonProperty("context") List<String> context,
            @JsonProperty("type") List<String> type
    ) {}

    @Builder
    public record ProofTypeConfig(
            @JsonProperty("proof_signing_alg_values_supported") Set<String> proofSigningAlgValuesSupported
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CredentialMetadata(
            @JsonProperty("display") List<DisplayInfo> display,
            @JsonProperty("claims") List<ClaimDefinition> claims
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record DisplayInfo(
            @JsonProperty("name") String name,
            @JsonProperty("locale") String locale,
            @JsonProperty("description") String description,
            @JsonProperty("logo") DisplayImage logo,
            @JsonProperty("background_color") String backgroundColor,
            @JsonProperty("background_image") DisplayImage backgroundImage,
            @JsonProperty("text_color") String textColor
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record DisplayImage(
            @JsonProperty("uri") String uri,
            @JsonProperty("alt_text") String altText
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ClaimDefinition(
            @JsonProperty("path") List<String> path,
            @JsonProperty("display") List<DisplayInfo> display
    ) {}

    public enum IssuerType {
        @JsonProperty("DETAILED") DETAILED,
        @JsonProperty("SIMPLE") SIMPLE
    }

    @Builder
    public record SubjectExtraction(
            @JsonProperty("strategy") String strategy,
            @JsonProperty("fields") List<String> fields,
            @JsonProperty("separator") String separator,
            @JsonProperty("last_segment_delimiter") String lastSegmentDelimiter
    ) {}

    @Builder
    public record OrganizationExtraction(
            @JsonProperty("strategy") String strategy,
            @JsonProperty("field") String field
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SdJwtConfig(
            @JsonProperty("vct") String vct,
            @JsonProperty("sd_alg") String sdAlg,
            @JsonProperty("sd_claims") List<String> sdClaims
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyExtraction(
            @JsonProperty("powers_path") String powersPath,
            @JsonProperty("mandator_path") String mandatorPath,
            @JsonProperty("org_id_field") String orgIdField
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Validation(
            @JsonProperty("mandator_org_id_path") String mandatorOrgIdPath
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record IssuancePolicy(
            @JsonProperty("policy_group") String policyGroup,
            @JsonProperty("required_emitter_config_ids") List<String> requiredEmitterConfigIds,
            @JsonProperty("rules") List<String> rules,
            @JsonProperty("delegation_function") String delegationFunction
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record TokenClaimsMapping(
            @JsonProperty("id_token") Map<String, Object> idToken,
            @JsonProperty("access_token") Map<String, Object> accessToken,
            @JsonProperty("scope") String scope
    ) {}

    /**
     * {@code true} when this credential type is cryptographically bound to a holder key.
     *
     * <p>{@code proof_types_supported} is the single signal behind that question (ADR-110): it is the
     * field obliging the wallet to send a signed key proof, and the key the issuer builds {@code cnf}
     * from comes out of that proof. Absent, there is no key to bind -- and the type is therefore
     * eligible for direct delivery, which has neither wallet nor proof.
     *
     * <p>Read this rather than {@code cryptographic_binding_methods_supported} (which describes how key
     * material is represented, not whether it is required) or {@code cnfRequired} (a write switch
     * subordinate to this signal). Keeping the null/empty check here means the three call sites that
     * used to answer it three different ways now cannot disagree.
     */
    public boolean requiresHolderBinding() {
        return proofTypesSupported != null && !proofTypesSupported.isEmpty();
    }

    /**
     * Returns the credential type name (e.g., "learcredential.employee.w3c.4").
     * Derived from the second element in credential_definition.type,
     * or the first element if only one type is defined.
     */
    public String credentialType() {
        if (credentialDefinition == null || credentialDefinition.type() == null || credentialDefinition.type().isEmpty()) {
            return credentialConfigurationId;
        }
        List<String> types = credentialDefinition.type();
        for (String type : types) {
            if (!"VerifiableCredential".equals(type)) {
                return type;
            }
        }
        return types.getFirst();
    }
}
