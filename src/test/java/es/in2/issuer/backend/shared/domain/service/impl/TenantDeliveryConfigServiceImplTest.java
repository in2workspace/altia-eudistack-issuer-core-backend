package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.model.entities.TenantConfig;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantConfigRepository;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TenantDeliveryConfigServiceImplTest {

    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String EXPECTED_KEY = "issuer.delivery.modes." + CONFIG_ID;

    @Mock
    private TenantConfigRepository tenantConfigRepository;

    @Mock
    private SchemaDeliveryCeiling schemaDeliveryCeiling;

    private TenantDeliveryConfigServiceImpl service;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        service = new TenantDeliveryConfigServiceImpl(tenantConfigRepository, schemaDeliveryCeiling);
    }

    @Nested
    class GetEligibleModes {

        @Test
        void getEligibleModes_keyPresent_returnsParsedModes() {
            TenantConfig existing = new TenantConfig(UUID.randomUUID(), EXPECTED_KEY, "direct,email", null, Instant.now(), Instant.now());
            when(tenantConfigRepository.findByConfigKey(EXPECTED_KEY)).thenReturn(Mono.just(existing));

            StepVerifier.create(service.getEligibleModes(CONFIG_ID))
                    .assertNext(modes -> assertEquals(Set.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL), modes))
                    .verifyComplete();
        }

        @Test
        void getEligibleModes_keyAbsent_completesEmpty() {
            when(tenantConfigRepository.findByConfigKey(EXPECTED_KEY)).thenReturn(Mono.empty());

            StepVerifier.create(service.getEligibleModes(CONFIG_ID))
                    .verifyComplete();
        }

        @Test
        void getEligibleModes_repositoryFails_propagatesErrorInsteadOfEmpty() {
            when(tenantConfigRepository.findByConfigKey(EXPECTED_KEY))
                    .thenReturn(Mono.error(new RuntimeException("connection refused")));

            StepVerifier.create(service.getEligibleModes(CONFIG_ID))
                    .expectError(RuntimeException.class)
                    .verify();
        }
    }

    @Nested
    class SetEligibleModes {

        @Test
        void setEligibleModes_nullSet_throwsInvalidDeliveryConfigExceptionWithoutTouchingRepository() {
            StepVerifier.create(service.setEligibleModes(CONFIG_ID, null))
                    .expectError(InvalidDeliveryConfigException.class)
                    .verify();

            verifyNoInteractions(tenantConfigRepository);
        }

        @Test
        void setEligibleModes_emptySet_throwsInvalidDeliveryConfigExceptionWithoutTouchingRepository() {
            StepVerifier.create(service.setEligibleModes(CONFIG_ID, Set.of()))
                    .expectError(InvalidDeliveryConfigException.class)
                    .verify();

            verifyNoInteractions(tenantConfigRepository);
        }

        @Test
        void setEligibleModes_keyAbsent_insertsNewRowWithNullId() {
            when(tenantConfigRepository.findByConfigKey(EXPECTED_KEY)).thenReturn(Mono.empty());
            when(tenantConfigRepository.save(any(TenantConfig.class)))
                    .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

            StepVerifier.create(service.setEligibleModes(CONFIG_ID, EnumSet.of(DeliveryMode.EMAIL)))
                    .verifyComplete();

            ArgumentCaptor<TenantConfig> captor = ArgumentCaptor.forClass(TenantConfig.class);
            verify(tenantConfigRepository).save(captor.capture());
            assertNull(captor.getValue().id());
            assertEquals(EXPECTED_KEY, captor.getValue().configKey());
            assertEquals("email", captor.getValue().configValue());
        }

        @Test
        void setEligibleModes_keyPresent_updatesExistingRowPreservingId() {
            UUID existingId = UUID.randomUUID();
            Instant createdAt = Instant.now().minusSeconds(3600);
            TenantConfig existing = new TenantConfig(existingId, EXPECTED_KEY, "email", "desc", createdAt, createdAt);
            when(tenantConfigRepository.findByConfigKey(EXPECTED_KEY)).thenReturn(Mono.just(existing));
            when(tenantConfigRepository.save(any(TenantConfig.class)))
                    .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

            StepVerifier.create(service.setEligibleModes(CONFIG_ID, EnumSet.of(DeliveryMode.DIRECT, DeliveryMode.UI)))
                    .verifyComplete();

            ArgumentCaptor<TenantConfig> captor = ArgumentCaptor.forClass(TenantConfig.class);
            verify(tenantConfigRepository).save(captor.capture());
            assertEquals(existingId, captor.getValue().id());
            assertEquals("desc", captor.getValue().description());
            assertEquals("direct,ui", captor.getValue().configValue());
        }

        @Test
        void setEligibleModes_replacesRatherThanMerges() {
            UUID existingId = UUID.randomUUID();
            TenantConfig existing = new TenantConfig(existingId, EXPECTED_KEY, "direct,email,ui", null, Instant.now(), Instant.now());
            when(tenantConfigRepository.findByConfigKey(EXPECTED_KEY)).thenReturn(Mono.just(existing));
            when(tenantConfigRepository.save(any(TenantConfig.class)))
                    .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

            StepVerifier.create(service.setEligibleModes(CONFIG_ID, EnumSet.of(DeliveryMode.EMAIL)))
                    .verifyComplete();

            ArgumentCaptor<TenantConfig> captor = ArgumentCaptor.forClass(TenantConfig.class);
            verify(tenantConfigRepository).save(captor.capture());
            assertEquals("email", captor.getValue().configValue());
        }

        @Test
        void setEligibleModes_reappliedWithSameValue_isIdempotent() {
            TenantConfig existing = new TenantConfig(UUID.randomUUID(), EXPECTED_KEY, "email", null, Instant.now(), Instant.now());
            when(tenantConfigRepository.findByConfigKey(EXPECTED_KEY)).thenReturn(Mono.just(existing));
            when(tenantConfigRepository.save(any(TenantConfig.class)))
                    .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));

            StepVerifier.create(service.setEligibleModes(CONFIG_ID, EnumSet.of(DeliveryMode.EMAIL)))
                    .verifyComplete();

            verify(tenantConfigRepository, times(1)).save(any(TenantConfig.class));
        }
    }

    @Nested
    class KeyIsolation {

        @Test
        void differentCredentialConfigurationIds_useDistinctConfigKeys() {
            String otherConfigId = "learcredential.machine.w3c.1";
            when(tenantConfigRepository.findByConfigKey(anyString())).thenReturn(Mono.empty());

            StepVerifier.create(service.getEligibleModes(CONFIG_ID)).verifyComplete();
            StepVerifier.create(service.getEligibleModes(otherConfigId)).verifyComplete();

            verify(tenantConfigRepository).findByConfigKey(EXPECTED_KEY);
            verify(tenantConfigRepository).findByConfigKey("issuer.delivery.modes." + otherConfigId);
        }
    }

    @Nested
    class CeilingOnWrites {

        /**
         * AC-05. Rejecting at the boundary rather than storing and ignoring: a persisted mode above the
         * schema ceiling reads as enabled to whoever inspects the configuration later, which is exactly
         * the divergence between stored policy and real behaviour that ADR-110 closes.
         */
        @Test
        void setEligibleModes_directOnBoundType_rejectsWithoutTouchingTheRepository() {
            doThrow(new DeliveryModeNotEligibleException("direct not eligible for " + CONFIG_ID))
                    .when(schemaDeliveryCeiling).validateWithinCeiling(eq(CONFIG_ID), any());

            StepVerifier.create(service.setEligibleModes(CONFIG_ID, EnumSet.of(DeliveryMode.DIRECT)))
                    .expectError(DeliveryModeNotEligibleException.class)
                    .verify();

            verify(tenantConfigRepository, never()).save(any());
        }

        @Test
        void setEligibleModes_withinCeiling_persistsNormally() {
            when(tenantConfigRepository.findByConfigKey(EXPECTED_KEY)).thenReturn(Mono.empty());
            when(tenantConfigRepository.save(any(TenantConfig.class)))
                    .thenAnswer(inv -> Mono.just(inv.getArgument(0, TenantConfig.class)));

            StepVerifier.create(service.setEligibleModes(CONFIG_ID, EnumSet.of(DeliveryMode.EMAIL)))
                    .verifyComplete();

            verify(tenantConfigRepository).save(any(TenantConfig.class));
        }
    }
}
