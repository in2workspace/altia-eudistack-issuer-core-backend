package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.DeliveryConfigProfileNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.DeliveryEligibilityResolver;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.service.TenantDeliveryConfigService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.controller.dto.DeliveryConfigDto;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DeliveryConfigControllerTest {

    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String AUTH_HEADER = "Bearer token";

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private TenantCredentialProfileService tenantCredentialProfileService;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @Mock
    private TenantDeliveryConfigService tenantDeliveryConfigService;

    @Mock
    private DeliveryEligibilityResolver deliveryEligibilityResolver;

    @Mock
    private SchemaDeliveryCeiling schemaDeliveryCeiling;

    @InjectMocks
    private DeliveryConfigController controller;

    private static AuthorizationContext tenantAdmin() {
        return new AuthorizationContext("VATES-A78446333", UserRole.TENANT_ADMIN, false, "simple");
    }

    private static AuthorizationContext lear() {
        return new AuthorizationContext("VATES-A78446333", UserRole.LEAR, false, "simple");
    }

    private void mockKnownAllowedProfile() {
        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID))
                .thenReturn(CredentialProfile.builder().credentialConfigurationId(CONFIG_ID).build());
        when(tenantCredentialProfileService.isProfileAllowed(CONFIG_ID)).thenReturn(Mono.just(true));
    }

    @Nested
    class GetDeliveryConfig {

        @Test
        void get_tenantAdminAndAllowedProfile_returnsCanonicalSortedModes() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(tenantAdmin()));
            mockKnownAllowedProfile();
            when(deliveryEligibilityResolver.resolveEligibleModes(CONFIG_ID))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.UI, DeliveryMode.DIRECT)));

            when(schemaDeliveryCeiling.resolveEligibleModes(CONFIG_ID))
                    .thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

            StepVerifier.create(controller.getDeliveryConfig(AUTH_HEADER, CONFIG_ID))
                    .assertNext(dto -> {
                        assertEquals(CONFIG_ID, dto.credentialConfigurationId());
                        assertEquals(List.of("direct", "ui"), dto.eligibleModes());
                        // AC-11: the ceiling travels with the read so a TenantAdmin can see why a mode is
                        // unavailable instead of discovering it through a rejected write.
                        assertEquals(List.of("email", "ui"), dto.schemaEligibleModes());
                    })
                    .verifyComplete();
        }

        @Test
        void get_callerNotTenantAdmin_rejectsWithForbiddenBeforeReadingConfig() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(lear()));

            StepVerifier.create(controller.getDeliveryConfig(AUTH_HEADER, CONFIG_ID))
                    .expectErrorSatisfies(e -> {
                        var rse = (ResponseStatusException) e;
                        assertEquals(HttpStatus.FORBIDDEN, rse.getStatusCode());
                    })
                    .verify();

            verifyNoInteractions(deliveryEligibilityResolver, tenantDeliveryConfigService);
        }

        @Test
        void get_unknownCredentialConfigurationId_rejectsWithProfileNotFound() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(tenantAdmin()));
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(null);

            StepVerifier.create(controller.getDeliveryConfig(AUTH_HEADER, CONFIG_ID))
                    .expectError(DeliveryConfigProfileNotFoundException.class)
                    .verify();

            verifyNoInteractions(deliveryEligibilityResolver);
        }

        @Test
        void get_profileNotEnabledForTenant_rejectsWithProfileNotFound() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(tenantAdmin()));
            when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID))
                    .thenReturn(CredentialProfile.builder().credentialConfigurationId(CONFIG_ID).build());
            when(tenantCredentialProfileService.isProfileAllowed(CONFIG_ID)).thenReturn(Mono.just(false));

            StepVerifier.create(controller.getDeliveryConfig(AUTH_HEADER, CONFIG_ID))
                    .expectError(DeliveryConfigProfileNotFoundException.class)
                    .verify();

            verifyNoInteractions(deliveryEligibilityResolver);
        }
    }

    @Nested
    class SetDeliveryConfig {

        @Test
        void put_validHybridModes_persistsParsedSetAndReturnsCanonicalDto() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(tenantAdmin()));
            mockKnownAllowedProfile();
            when(tenantDeliveryConfigService.setEligibleModes(eq(CONFIG_ID), anySet())).thenReturn(Mono.empty());
            DeliveryConfigDto request = DeliveryConfigDto.builder()
                    .eligibleModes(List.of("direct", "email"))
                    .build();

            StepVerifier.create(controller.setDeliveryConfig(AUTH_HEADER, CONFIG_ID, request))
                    .assertNext(dto -> assertEquals(List.of("direct", "email"), dto.eligibleModes()))
                    .verifyComplete();

            verify(tenantDeliveryConfigService).setEligibleModes(CONFIG_ID, Set.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL));
        }

        @Test
        void put_unknownModeValue_rejectsWithInvalidDeliveryConfigWithoutPersisting() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(tenantAdmin()));
            mockKnownAllowedProfile();
            DeliveryConfigDto request = DeliveryConfigDto.builder()
                    .eligibleModes(List.of("carrier-pigeon"))
                    .build();

            StepVerifier.create(controller.setDeliveryConfig(AUTH_HEADER, CONFIG_ID, request))
                    .expectError(InvalidDeliveryConfigException.class)
                    .verify();

            verifyNoInteractions(tenantDeliveryConfigService);
        }

        @Test
        void put_emptyModesList_rejectsWithInvalidDeliveryConfigWithoutPersisting() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(tenantAdmin()));
            mockKnownAllowedProfile();
            DeliveryConfigDto request = DeliveryConfigDto.builder()
                    .eligibleModes(List.of())
                    .build();

            StepVerifier.create(controller.setDeliveryConfig(AUTH_HEADER, CONFIG_ID, request))
                    .expectError(InvalidDeliveryConfigException.class)
                    .verify();

            verifyNoInteractions(tenantDeliveryConfigService);
        }

        @Test
        void put_bodyCredentialConfigurationIdMismatchesPath_rejectsWithInvalidDeliveryConfigWithoutPersisting() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(tenantAdmin()));
            mockKnownAllowedProfile();
            DeliveryConfigDto request = DeliveryConfigDto.builder()
                    .credentialConfigurationId("some.other.credential.type")
                    .eligibleModes(List.of("email"))
                    .build();

            StepVerifier.create(controller.setDeliveryConfig(AUTH_HEADER, CONFIG_ID, request))
                    .expectError(InvalidDeliveryConfigException.class)
                    .verify();

            verifyNoInteractions(tenantDeliveryConfigService);
        }

        @Test
        void put_bodyCredentialConfigurationIdMatchesPath_persistsNormally() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(tenantAdmin()));
            mockKnownAllowedProfile();
            when(tenantDeliveryConfigService.setEligibleModes(eq(CONFIG_ID), anySet())).thenReturn(Mono.empty());
            DeliveryConfigDto request = DeliveryConfigDto.builder()
                    .credentialConfigurationId(CONFIG_ID)
                    .eligibleModes(List.of("email"))
                    .build();

            StepVerifier.create(controller.setDeliveryConfig(AUTH_HEADER, CONFIG_ID, request))
                    .assertNext(dto -> assertEquals(List.of("email"), dto.eligibleModes()))
                    .verifyComplete();

            verify(tenantDeliveryConfigService).setEligibleModes(CONFIG_ID, Set.of(DeliveryMode.EMAIL));
        }

        @Test
        void put_callerNotTenantAdmin_rejectsWithForbiddenWithoutPersisting() {
            when(accessTokenService.getAuthorizationContext(AUTH_HEADER)).thenReturn(Mono.just(lear()));
            DeliveryConfigDto request = DeliveryConfigDto.builder()
                    .eligibleModes(List.of("email"))
                    .build();

            StepVerifier.create(controller.setDeliveryConfig(AUTH_HEADER, CONFIG_ID, request))
                    .expectErrorSatisfies(e -> {
                        var rse = (ResponseStatusException) e;
                        assertEquals(HttpStatus.FORBIDDEN, rse.getStatusCode());
                    })
                    .verify();

            verifyNoInteractions(tenantDeliveryConfigService);
        }
    }
}
