package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.util.TenantIdentifiers;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

/**
 * Creates a PolicyContext from a JWT access token with flat claims.
 * The access token contains top-level claims: credential_type, mandator, power, tenant.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PolicyContextFactory {

    private static final String CREDENTIAL_TYPE_CLAIM = "credential_type";
    private static final String POWER_CLAIM = "power";
    private static final String MANDATOR_CLAIM = "mandator";
    private static final String ORG_ID_FIELD = "organizationIdentifier";
    private static final String TENANT_CLAIM = "tenant";

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;
    private final IssuerProperties appConfig;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final TenantConfigService tenantConfigService;
    private final TenantRegistryService tenantRegistryService;

    /**
     * Creates a PolicyContext from a JWT token for Issuance and StatusList PDPs.
     */
    public Mono<PolicyContext> fromTokenSimple(String token, String tenantDomain) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String credentialType = extractCredentialType(signedJWT.getPayload());
                    CredentialProfile profile = resolveProfile(credentialType);
                    List<Power> powers = extractPowers(signedJWT.getPayload());
                    String orgId = extractOrganizationId(signedJWT.getPayload());
                    String tokenTenant = extractTokenTenant(signedJWT.getPayload());
                    JsonNode credential = buildCredentialNode(signedJWT.getPayload());

                    log.info("User organization identifier: {}", orgId);

                    boolean isSysAdmin = hasSysAdminPower(powers);

                    return Mono.zip(
                            resolveTenantAdmin(orgId, powers, tenantDomain),
                            resolveTenantType(tenantDomain)
                    ).map(tuple -> new PolicyContext(
                            orgId, powers, credential, profile, credentialType,
                            isSysAdmin, tuple.getT1(), tenantDomain, tokenTenant, tuple.getT2()
                    ));
                });
    }

    /**
     * Creates a PolicyContext from a JWT token for IssuancePdpService.
     * Validates that the emitter's credential type is allowed to issue the target credential,
     * using the target profile's issuance_policy.required_emitter_config_ids.
     */
    public Mono<PolicyContext> fromTokenForIssuance(String token, String credentialConfigurationId, String tenantDomain) {
        return Mono.fromCallable(() -> jwtService.parseJWT(token))
                .flatMap(signedJWT -> {
                    String credentialType = extractCredentialType(signedJWT.getPayload());

                    return checkIfEmitterIsAllowedToIssue(credentialType, credentialConfigurationId)
                            .flatMap(resolvedType -> {
                                CredentialProfile profile = resolveProfile(credentialType);
                                List<Power> powers = extractPowers(signedJWT.getPayload());
                                String orgId = extractOrganizationId(signedJWT.getPayload());
                                String tokenTenant = extractTokenTenant(signedJWT.getPayload());
                                JsonNode credential = buildCredentialNode(signedJWT.getPayload());

                                boolean isSysAdmin = hasSysAdminPower(powers);

                                return Mono.zip(
                                        resolveTenantAdmin(orgId, powers, tenantDomain),
                                        resolveTenantType(tenantDomain)
                                ).map(tuple -> new PolicyContext(
                                        orgId, powers, credential, profile, resolvedType,
                                        isSysAdmin, tuple.getT1(), tenantDomain, tokenTenant, tuple.getT2()
                                ));
                            });
                });
    }

    /**
     * Extracts the credential_type claim from the token payload.
     * The claim is a plain string like "learcredential.employee.w3c.4".
     * getClaimFromPayload serializes via ObjectMapper, so strings come back with surrounding quotes.
     */
    private String extractCredentialType(com.nimbusds.jose.Payload payload) {
        String raw = jwtService.getClaimFromPayload(payload, CREDENTIAL_TYPE_CLAIM);
        return stripJsonQuotes(raw);
    }

    /**
     * Extracts the power array from the token payload and deserializes to List of Power.
     */
    private List<Power> extractPowers(com.nimbusds.jose.Payload payload) {
        try {
            String powerJson = jwtService.getClaimFromPayload(payload, POWER_CLAIM);
            return objectMapper.readValue(powerJson, new TypeReference<>() {});
        } catch (Exception e) {
            log.debug("No power claim found in token or failed to parse: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Extracts the organization identifier from the mandator claim.
     * The mandator is a JSON object with an organizationIdentifier field.
     */
    private String extractOrganizationId(com.nimbusds.jose.Payload payload) {
        try {
            String mandatorJson = jwtService.getClaimFromPayload(payload, MANDATOR_CLAIM);
            JsonNode mandatorNode = objectMapper.readTree(mandatorJson);
            JsonNode orgIdNode = mandatorNode.path(ORG_ID_FIELD);
            return orgIdNode.isMissingNode() || orgIdNode.isNull() ? null : orgIdNode.asText();
        } catch (Exception e) {
            log.debug("No mandator claim found in token or failed to parse: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extracts the tenant claim from the token payload.
     * The verifier injects this claim based on the OIDC client's tenant configuration.
     *
     * <p>Normalized the same way {@code TenantDomainWebFilter} already normalizes the resolved
     * tenant side (M3, re-verification): a legacy env-suffixed claim (e.g. {@code "sandbox-stg"})
     * must not fail {@link es.in2.issuer.backend.shared.domain.policy.rules.RequireTenantMatchRule}'s
     * comparison on formatting alone.
     */
    private String extractTokenTenant(com.nimbusds.jose.Payload payload) {
        try {
            String raw = jwtService.getClaimFromPayload(payload, TENANT_CLAIM);
            return TenantIdentifiers.stripEnvSuffix(stripJsonQuotes(raw));
        } catch (Exception e) {
            log.debug("No tenant claim found in token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Builds a JsonNode from the flat token claims to serve as the credential field in PolicyContext.
     * Includes credential_type, mandator, and power claims.
     */
    private JsonNode buildCredentialNode(com.nimbusds.jose.Payload payload) {
        ObjectNode node = objectMapper.createObjectNode();
        try {
            String credentialType = jwtService.getClaimFromPayload(payload, CREDENTIAL_TYPE_CLAIM);
            node.put(CREDENTIAL_TYPE_CLAIM, stripJsonQuotes(credentialType));
        } catch (Exception e) {
            // credential_type missing, leave empty
        }
        try {
            String mandatorJson = jwtService.getClaimFromPayload(payload, MANDATOR_CLAIM);
            node.set(MANDATOR_CLAIM, objectMapper.readTree(mandatorJson));
        } catch (Exception e) {
            // mandator missing, leave empty
        }
        try {
            String powerJson = jwtService.getClaimFromPayload(payload, POWER_CLAIM);
            node.set(POWER_CLAIM, objectMapper.readTree(powerJson));
        } catch (Exception e) {
            // power missing, leave empty
        }
        return node;
    }

    private CredentialProfile resolveProfile(String credentialType) {
        CredentialProfile profile = credentialProfileRegistry.resolveProfile(credentialType);
        if (profile == null) {
            throw new InvalidCredentialFormatException(
                    "No profile found for credential type: " + credentialType);
        }
        return profile;
    }

    /**
     * Checks that the emitter's credential type is in the target profile's required_emitter_config_ids.
     * If no issuance_policy is defined, accepts the emitter type directly.
     */
    private Mono<String> checkIfEmitterIsAllowedToIssue(String emitterCredentialType, String credentialConfigurationId) {
        CredentialProfile targetProfile = credentialProfileRegistry.getByConfigurationId(credentialConfigurationId);
        if (targetProfile != null && targetProfile.issuancePolicy() != null
                && targetProfile.issuancePolicy().requiredEmitterConfigIds() != null) {
            List<String> required = targetProfile.issuancePolicy().requiredEmitterConfigIds();
            if (required.contains(emitterCredentialType)) {
                return Mono.just(emitterCredentialType);
            }
            return Mono.error(new InsufficientPermissionException(
                    "Unauthorized: Emitter credential type [" + emitterCredentialType
                            + "] is not allowed to issue " + credentialConfigurationId
                            + ". Required: " + required));
        }
        // No issuance policy restriction: accept the emitter type
        return Mono.just(emitterCredentialType);
    }

    /**
     * Strips surrounding JSON quotes from a serialized string value.
     * getClaimFromPayload returns "\"value\"" for string claims.
     */
    private String stripJsonQuotes(String value) {
        if (value != null && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }

    /**
     * Resolves whether the presenter is the TenantAdmin for the current tenant.
     * A user is TenantAdmin when:
     *   1. Their organizationIdentifier matches the tenant's configured admin_organization_id; AND
     *   2. They hold an Onboarding/Execute power whose domain matches the current tenant.
     *
     * The domain check is what prevents a KPMG-issued credential (Onboarding/Execute for
     * domain=KPMG) from being accepted as TenantAdmin on a different tenant (e.g. DOME).
     */
    private Mono<Boolean> resolveTenantAdmin(String orgId, List<Power> powers, String tenantDomain) {
        if (orgId == null || tenantDomain == null || tenantDomain.isBlank()) {
            log.debug("TenantAdmin resolution skipped: orgId='{}', tenantDomain='{}'", orgId, tenantDomain);
            return Mono.just(false);
        }
        boolean hasDomainPower = powers.stream().anyMatch(p ->
                "Onboarding".equals(p.function())
                        && PolicyContext.hasAction(p, "Execute")
                        && tenantDomain.equalsIgnoreCase(p.domain()));
        log.debug("TenantAdmin resolution: orgId='{}', tenantDomain='{}', hasDomainOnboardingExecutePower={}",
                orgId, tenantDomain, hasDomainPower);
        if (!hasDomainPower) return Mono.just(false);

        return tenantConfigService.getStringOrThrow("admin_organization_id")
                .map(adminOrgId -> {
                    boolean match = orgId.equals(adminOrgId);
                    log.debug("TenantAdmin org check: operatorOrgId='{}', configAdminOrgId='{}', match={}",
                            orgId, adminOrgId, match);
                    return match;
                });
    }

    private Mono<String> resolveTenantType(String tenantDomain) {
        if (tenantDomain == null || tenantDomain.isBlank()) {
            return Mono.just(PolicyContext.TENANT_TYPE_SIMPLE);
        }
        return tenantRegistryService.getTenantType(tenantDomain)
                .defaultIfEmpty(PolicyContext.TENANT_TYPE_SIMPLE);
    }

    private boolean hasSysAdminPower(List<Power> powers) {
        return powers.stream().anyMatch(p ->
                "organization".equals(p.type())
                && "EUDISTACK".equals(p.domain())
                && "System".equals(p.function())
                && PolicyContext.hasAction(p, "Administration"));
    }
}
