package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PolicyContextFactoryTest {

    private static final String ADMIN_ORG_ID = "ADMIN_ORG";
    private static final String TOKEN = "test-token";
    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.4";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private JWTService jwtService;

    @Mock
    private IssuerProperties appConfig;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @Mock
    private TenantConfigService tenantConfigService;

    @Mock
    private TenantRegistryService tenantRegistryService;

    private PolicyContextFactory factory;

    @BeforeEach
    void setUp() {
        factory = new PolicyContextFactory(
                jwtService, objectMapper, appConfig, credentialProfileRegistry, tenantConfigService, tenantRegistryService
        );
        // Default stub: tenantConfigService returns the admin_organization_id from tenant_config
        lenient().when(tenantConfigService.getStringOrThrow(anyString()))
                .thenReturn(Mono.just(ADMIN_ORG_ID));
        lenient().when(tenantRegistryService.getTenantType(anyString()))
                .thenReturn(Mono.just(PolicyContext.TENANT_TYPE_MULTI_ORG));
    }

    private void setupFlatTokenClaims(Payload payload, String credentialType, String orgId) {
        setupFlatTokenClaims(payload, credentialType, orgId, "DOME");
    }

    private void setupFlatTokenClaims(Payload payload, String credentialType, String orgId, String tenant) {
        // credential_type claim: getClaimFromPayload serializes strings with quotes
        when(jwtService.getClaimFromPayload(payload, "credential_type"))
                .thenReturn("\"" + credentialType + "\"");

        // power claim: JSON array
        String powerJson = "[{\"function\":\"Onboarding\",\"action\":\"Execute\",\"domain\":\"DOME\",\"type\":\"Domain\"}]";
        when(jwtService.getClaimFromPayload(payload, "power")).thenReturn(powerJson);

        // mandator claim: JSON object
        String mandatorJson = "{\"organizationIdentifier\":\"" + orgId + "\",\"organization\":\"Test Org\"}";
        when(jwtService.getClaimFromPayload(payload, "mandator")).thenReturn(mandatorJson);

        // tenant claim: plain string (with quotes from serialization)
        if (tenant != null) {
            when(jwtService.getClaimFromPayload(payload, "tenant")).thenReturn("\"" + tenant + "\"");
        }
    }

    private CredentialProfile buildProfile(String configId) {
        return CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .policyExtraction(CredentialProfile.PolicyExtraction.builder()
                        .powersPath("power")
                        .mandatorPath("mandator")
                        .orgIdField("organizationIdentifier")
                        .build())
                .build();
    }

    // --- fromTokenSimple ---

    @Test
    void fromTokenSimple_createsContextWithPowers() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        setupFlatTokenClaims(payload, CREDENTIAL_TYPE, "ORG-123");

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.resolveProfile(CREDENTIAL_TYPE)).thenReturn(profile);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.organizationIdentifier()).isEqualTo("ORG-123");
                    assertThat(ctx.credentialType()).isEqualTo(CREDENTIAL_TYPE);
                    assertThat(ctx.sysAdmin()).isFalse();
                    assertThat(ctx.powers()).hasSize(1);
                    assertThat(ctx.powers().getFirst().function()).isEqualTo("Onboarding");
                    assertThat(ctx.tenantDomain()).isEqualTo("DOME");
                    assertThat(ctx.tokenTenant()).isEqualTo("DOME");
                    assertThat(ctx.profile()).isEqualTo(profile);
                    assertThat(ctx.credential()).isNotNull();
                })
                .verifyComplete();
    }

    @Test
    void fromTokenSimple_tokenTenantWithLegacyEnvSuffix_isStripped() {
        // M3 (re-verification): normalized the same way TenantDomainWebFilter already
        // normalizes the resolved-tenant side, so a legacy env-suffixed claim doesn't fail
        // RequireTenantMatchRule's comparison on formatting alone.
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        setupFlatTokenClaims(payload, CREDENTIAL_TYPE, "ORG-123", "DOME-stg");

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.resolveProfile(CREDENTIAL_TYPE)).thenReturn(profile);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> assertThat(ctx.tokenTenant()).isEqualTo("DOME"))
                .verifyComplete();
    }

    @Test
    void fromTokenSimple_tokenTenantIsNullWhenClaimAbsent() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        setupFlatTokenClaims(payload, CREDENTIAL_TYPE, "ORG-123", null);

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.resolveProfile(CREDENTIAL_TYPE)).thenReturn(profile);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.tokenTenant()).isNull();
                    assertThat(ctx.tenantDomain()).isEqualTo("DOME");
                })
                .verifyComplete();
    }

    @Test
    void fromTokenSimple_setsIsSysAdminWhenHasOrganizationEudistackPower() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        // SysAdmin power: organization/EUDISTACK/System/Administration
        when(jwtService.getClaimFromPayload(payload, "credential_type"))
                .thenReturn("\"" + CREDENTIAL_TYPE + "\"");
        String powerJson = "[{\"type\":\"organization\",\"domain\":\"EUDISTACK\",\"function\":\"System\",\"action\":[\"Administration\"]}]";
        when(jwtService.getClaimFromPayload(payload, "power")).thenReturn(powerJson);
        String mandatorJson = "{\"organizationIdentifier\":\"" + ADMIN_ORG_ID + "\",\"organization\":\"Test Org\"}";
        when(jwtService.getClaimFromPayload(payload, "mandator")).thenReturn(mandatorJson);
        when(jwtService.getClaimFromPayload(payload, "tenant")).thenReturn("\"DOME\"");

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.resolveProfile(CREDENTIAL_TYPE)).thenReturn(profile);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.sysAdmin()).isTrue();
                    assertThat(ctx.organizationIdentifier()).isEqualTo(ADMIN_ORG_ID);
                })
                .verifyComplete();
    }

    @Test
    void fromTokenSimple_notSysAdminWithOnboardingPowerOnly() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        // Onboarding power but NOT organization/EUDISTACK → not sysAdmin
        when(jwtService.getClaimFromPayload(payload, "credential_type"))
                .thenReturn("\"" + CREDENTIAL_TYPE + "\"");
        String powerJson = "[{\"function\":\"Onboarding\",\"action\":\"Execute\",\"domain\":\"DOME\",\"type\":\"domain\"}]";
        when(jwtService.getClaimFromPayload(payload, "power")).thenReturn(powerJson);
        String mandatorJson = "{\"organizationIdentifier\":\"" + ADMIN_ORG_ID + "\",\"organization\":\"Test Org\"}";
        when(jwtService.getClaimFromPayload(payload, "mandator")).thenReturn(mandatorJson);

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.resolveProfile(CREDENTIAL_TYPE)).thenReturn(profile);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.sysAdmin()).isFalse();
                    assertThat(ctx.tenantAdmin()).isTrue();
                    assertThat(ctx.organizationIdentifier()).isEqualTo(ADMIN_ORG_ID);
                })
                .verifyComplete();
    }

    @Test
    void fromTokenSimple_tenantAdminFalseWhenPowerDomainDoesNotMatchTenant() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        // Onboarding/Execute power with domain=KPMG but user is logging in at DOME tenant.
        when(jwtService.getClaimFromPayload(payload, "credential_type"))
                .thenReturn("\"" + CREDENTIAL_TYPE + "\"");
        String powerJson = "[{\"function\":\"Onboarding\",\"action\":\"Execute\",\"domain\":\"KPMG\",\"type\":\"domain\"}]";
        when(jwtService.getClaimFromPayload(payload, "power")).thenReturn(powerJson);
        String mandatorJson = "{\"organizationIdentifier\":\"" + ADMIN_ORG_ID + "\",\"organization\":\"Test Org\"}";
        when(jwtService.getClaimFromPayload(payload, "mandator")).thenReturn(mandatorJson);
        when(jwtService.getClaimFromPayload(payload, "tenant")).thenReturn("\"DOME\"");

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.resolveProfile(CREDENTIAL_TYPE)).thenReturn(profile);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.sysAdmin()).isFalse();
                    assertThat(ctx.tenantAdmin())
                            .as("KPMG-domain power must not grant TenantAdmin on DOME tenant")
                            .isFalse();
                })
                .verifyComplete();
    }

    @Test
    void fromTokenSimple_tenantAdminDomainCheckIsCaseInsensitive() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        // Power domain "dome" (lowercase) vs tenantDomain "DOME" (uppercase)
        when(jwtService.getClaimFromPayload(payload, "credential_type"))
                .thenReturn("\"" + CREDENTIAL_TYPE + "\"");
        String powerJson = "[{\"function\":\"Onboarding\",\"action\":\"Execute\",\"domain\":\"dome\",\"type\":\"domain\"}]";
        when(jwtService.getClaimFromPayload(payload, "power")).thenReturn(powerJson);
        String mandatorJson = "{\"organizationIdentifier\":\"" + ADMIN_ORG_ID + "\",\"organization\":\"Test Org\"}";
        when(jwtService.getClaimFromPayload(payload, "mandator")).thenReturn(mandatorJson);
        when(jwtService.getClaimFromPayload(payload, "tenant")).thenReturn("\"DOME\"");

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.resolveProfile(CREDENTIAL_TYPE)).thenReturn(profile);

        StepVerifier.create(factory.fromTokenSimple(TOKEN, "DOME"))
                .assertNext(ctx -> assertThat(ctx.tenantAdmin()).isTrue())
                .verifyComplete();
    }

    // --- fromTokenForIssuance ---

    @Test
    void fromTokenForIssuance_createsContextWithPowers() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        setupFlatTokenClaims(payload, CREDENTIAL_TYPE, "ORG-123");

        CredentialProfile profile = buildProfile(CREDENTIAL_TYPE);
        when(credentialProfileRegistry.resolveProfile(CREDENTIAL_TYPE)).thenReturn(profile);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, CREDENTIAL_TYPE, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.credentialType()).isEqualTo(CREDENTIAL_TYPE);
                    assertThat(ctx.tenantDomain()).isEqualTo("DOME");
                    assertThat(ctx.powers()).hasSize(1);
                })
                .verifyComplete();
    }

    @Test
    void fromTokenForIssuance_failsWhenCredentialTypeNotAllowedForLabelCredential() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        // Emitter has learcredential.employee.w3c.4
        when(jwtService.getClaimFromPayload(payload, "credential_type"))
                .thenReturn("\"" + CREDENTIAL_TYPE + "\"");

        // Target profile requires learcredential.machine.w3c.3
        CredentialProfile labelProfile = CredentialProfile.builder()
                .credentialConfigurationId("gx.labelcredential.w3c.1")
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .requiredEmitterConfigIds(List.of("learcredential.machine.w3c.3"))
                        .build())
                .build();
        when(credentialProfileRegistry.getByConfigurationId("gx.labelcredential.w3c.1")).thenReturn(labelProfile);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, "gx.labelcredential.w3c.1", "DOME"))
                .expectErrorMatches(e ->
                        e instanceof InsufficientPermissionException &&
                                e.getMessage().contains("learcredential.machine.w3c.3"))
                .verify();
    }

    @Test
    void fromTokenForIssuance_succeedsWhenEmitterTypeMatchesRequiredConfigId() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        String machineType = "learcredential.machine.w3c.3";
        setupFlatTokenClaims(payload, machineType, "ORG-456");

        // Target profile requires learcredential.machine.w3c.3 and emitter has it
        CredentialProfile labelProfile = CredentialProfile.builder()
                .credentialConfigurationId("gx.labelcredential.w3c.1")
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .requiredEmitterConfigIds(List.of(machineType))
                        .build())
                .build();
        when(credentialProfileRegistry.getByConfigurationId("gx.labelcredential.w3c.1")).thenReturn(labelProfile);

        CredentialProfile machineProfile = buildProfile(machineType);
        when(credentialProfileRegistry.resolveProfile(machineType)).thenReturn(machineProfile);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, "gx.labelcredential.w3c.1", "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.credentialType()).isEqualTo(machineType);
                    assertThat(ctx.organizationIdentifier()).isEqualTo("ORG-456");
                })
                .verifyComplete();
    }

    @Test
    void fromTokenForIssuance_acceptsAnyTypeWhenNoIssuancePolicy() {
        SignedJWT signedJWT = mock(SignedJWT.class);
        Payload payload = mock(Payload.class);

        when(jwtService.parseJWT(TOKEN)).thenReturn(signedJWT);
        when(signedJWT.getPayload()).thenReturn(payload);

        setupFlatTokenClaims(payload, CREDENTIAL_TYPE, "ORG-789");

        // Target profile without issuance policy
        CredentialProfile targetProfile = CredentialProfile.builder()
                .credentialConfigurationId(CREDENTIAL_TYPE)
                .build();
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE)).thenReturn(targetProfile);

        CredentialProfile emitterProfile = buildProfile(CREDENTIAL_TYPE);
        // Two distinct lookups on the same key: checkIfEmitterIsAllowedToIssue resolves the target
        // profile by configuration id, resolveProfile resolves the emitter profile leniently
        when(credentialProfileRegistry.resolveProfile(CREDENTIAL_TYPE)).thenReturn(emitterProfile);

        StepVerifier.create(factory.fromTokenForIssuance(TOKEN, CREDENTIAL_TYPE, "DOME"))
                .assertNext(ctx -> {
                    assertThat(ctx.credentialType()).isEqualTo(CREDENTIAL_TYPE);
                })
                .verifyComplete();
    }
}
