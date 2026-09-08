package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeliveryEligibilityResolverTest {

    private static final String BOUND = "learcredential.employee.w3c.4";
    private static final String UNBOUND = "gx.labelcredential.w3c.2";

    private static final Set<DeliveryMode> WALLET_ONLY = EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI);
    private static final Set<DeliveryMode> ALL_MODES = EnumSet.allOf(DeliveryMode.class);

    @Mock
    private TenantDeliveryConfigService tenantDeliveryConfigService;

    @Mock
    private SchemaDeliveryCeiling schemaDeliveryCeiling;

    @InjectMocks
    private DeliveryEligibilityResolver resolver;

    @Nested
    class DefaultsToTheCeiling {

        @Test
        void resolveEligibleModes_noConfigAndUnboundType_defaultsToEveryMode() {
            when(schemaDeliveryCeiling.resolveEligibleModes(UNBOUND)).thenReturn(ALL_MODES);
            when(tenantDeliveryConfigService.getEligibleModes(UNBOUND)).thenReturn(Mono.empty());

            StepVerifier.create(resolver.resolveEligibleModes(UNBOUND))
                    .assertNext(modes -> assertEquals(ALL_MODES, modes))
                    .verifyComplete();
        }

        @Test
        void resolveEligibleModes_noConfigAndBoundType_defaultsToWalletModesOnly() {
            when(schemaDeliveryCeiling.resolveEligibleModes(BOUND)).thenReturn(WALLET_ONLY);
            when(tenantDeliveryConfigService.getEligibleModes(BOUND)).thenReturn(Mono.empty());

            StepVerifier.create(resolver.resolveEligibleModes(BOUND))
                    .assertNext(modes -> assertEquals(WALLET_ONLY, modes))
                    .verifyComplete();
        }
    }

    @Nested
    class ConfigurationNarrowsButNeverWidens {

        @Test
        void resolveEligibleModes_configNarrowerThanCeiling_returnsTheConfiguredSubset() {
            when(schemaDeliveryCeiling.resolveEligibleModes(UNBOUND)).thenReturn(ALL_MODES);
            when(tenantDeliveryConfigService.getEligibleModes(UNBOUND))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.EMAIL)));

            StepVerifier.create(resolver.resolveEligibleModes(UNBOUND))
                    .assertNext(modes -> assertEquals(Set.of(DeliveryMode.EMAIL), modes))
                    .verifyComplete();
        }

        /**
         * The case the ceiling exists for (AC-04): a configuration written before the rule, still listing
         * {@code direct} for a bound type. Honouring it would let tenant configuration re-enable a mode the
         * schema forbids, which is precisely the divergence ADR-110 closes.
         */
        @Test
        void resolveEligibleModes_legacyConfigEnablingDirectOnBoundType_intersectsItAway() {
            when(schemaDeliveryCeiling.resolveEligibleModes(BOUND)).thenReturn(WALLET_ONLY);
            when(tenantDeliveryConfigService.getEligibleModes(BOUND))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL)));

            StepVerifier.create(resolver.resolveEligibleModes(BOUND))
                    .assertNext(modes -> assertEquals(Set.of(DeliveryMode.EMAIL), modes))
                    .verifyComplete();
        }

        @Test
        void resolveEligibleModes_configEntirelyAboveTheCeiling_returnsEmptyRatherThanTheCeiling() {
            when(schemaDeliveryCeiling.resolveEligibleModes(BOUND)).thenReturn(WALLET_ONLY);
            when(tenantDeliveryConfigService.getEligibleModes(BOUND))
                    .thenReturn(Mono.just(EnumSet.of(DeliveryMode.DIRECT)));

            // Empty is the honest answer: the tenant configured exactly one mode and the schema forbids it.
            // Falling back to the ceiling here would silently ignore the tenant's own policy.
            StepVerifier.create(resolver.resolveEligibleModes(BOUND))
                    .assertNext(modes -> assertEquals(Set.of(), modes))
                    .verifyComplete();
        }
    }

    @Nested
    class CeilingErrorsPropagateAsOnError {

        /**
         * Code review (EUD-168): the ceiling lookup must stay deferred inside the reactive chain, not run
         * eagerly when this method is called. Constructing the Mono here must not throw even though the
         * mocked ceiling always throws -- only subscribing (StepVerifier.create) may trigger it.
         */
        @Test
        void resolveEligibleModes_unknownConfigId_signalsOnErrorRatherThanThrowingAtAssembly() {
            when(schemaDeliveryCeiling.resolveEligibleModes("unknown"))
                    .thenThrow(new IllegalStateException("Unknown credential_configuration_id reached the delivery ceiling: unknown"));

            Mono<Set<DeliveryMode>> result = resolver.resolveEligibleModes("unknown");

            StepVerifier.create(result)
                    .expectError(IllegalStateException.class)
                    .verify();
        }
    }
}
