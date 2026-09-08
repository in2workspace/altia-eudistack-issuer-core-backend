package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resolves the delivery modes effectively eligible for a {@code credential_configuration_id}:
 * {@code tenant configuration ∩ schema ceiling}, with the ceiling as the default when no
 * configuration exists (ADR-110, EUD-168).
 *
 * <p>Intersecting rather than merely defaulting is the point. A configuration stored before the
 * ceiling existed may still list {@code direct} for a type whose schema forbids it; honouring it would
 * show the admin a mode that issuance rejects, which is exactly the divergence this replaces.
 *
 * <p>Issuance-time enforcement lives in {@code IssuanceWorkflowImpl#resolveAndValidateDeliveryModes}
 * and applies the same two rules in the same order, so the admin view can never promise what issuance
 * would refuse.
 */
@Service
@RequiredArgsConstructor
public class DeliveryEligibilityResolver {

    private final TenantDeliveryConfigService tenantDeliveryConfigService;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;

    public Mono<Set<DeliveryMode>> resolveEligibleModes(String credentialConfigurationId) {
        // Deferred rather than resolved eagerly above: schemaDeliveryCeiling.resolveEligibleModes can
        // throw for an unknown configuration ID, and a caller composing this Mono outside a defer of its
        // own must still see that failure as an onError signal, not an assembly-time exception.
        return Mono.fromSupplier(() -> schemaDeliveryCeiling.resolveEligibleModes(credentialConfigurationId))
                .flatMap(ceiling -> tenantDeliveryConfigService.getEligibleModes(credentialConfigurationId)
                        .<Set<DeliveryMode>>map(configured -> configured.stream()
                                .filter(ceiling::contains)
                                .collect(Collectors.toCollection(() -> EnumSet.noneOf(DeliveryMode.class))))
                        .switchIfEmpty(Mono.just(ceiling)));
    }

}
