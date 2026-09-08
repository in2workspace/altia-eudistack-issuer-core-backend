package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.model.entities.TenantConfig;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.service.TenantDeliveryConfigService;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantConfigRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class TenantDeliveryConfigServiceImpl implements TenantDeliveryConfigService {

    private static final String KEY_PREFIX = "issuer.delivery.modes.";

    private final TenantConfigRepository tenantConfigRepository;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;

    @Override
    public Mono<Set<DeliveryMode>> getEligibleModes(String credentialConfigurationId) {
        return tenantConfigRepository.findByConfigKey(keyFor(credentialConfigurationId))
                .map(TenantConfig::configValue)
                .map(DeliveryMode::parse);
    }

    @Override
    public Mono<Void> setEligibleModes(String credentialConfigurationId, Set<DeliveryMode> modes) {
        if (modes == null || modes.isEmpty()) {
            return Mono.error(new InvalidDeliveryConfigException("At least one delivery mode is required"));
        }
        // Reject at the boundary rather than storing a configuration issuance would ignore: a persisted
        // mode above the schema ceiling reads as enabled to whoever inspects the config later (EUD-168).
        try {
            schemaDeliveryCeiling.validateWithinCeiling(credentialConfigurationId, modes);
        } catch (DeliveryModeNotEligibleException ex) {
            return Mono.error(ex);
        }
        String key = keyFor(credentialConfigurationId);
        String csv = DeliveryMode.toCanonicalCsv(modes);

        return tenantConfigRepository.findByConfigKey(key)
                .flatMap(existing -> tenantConfigRepository.save(new TenantConfig(
                        existing.id(), key, csv, existing.description(), existing.createdAt(), Instant.now())))
                .switchIfEmpty(Mono.defer(() -> {
                    Instant now = Instant.now();
                    return tenantConfigRepository.save(new TenantConfig(null, key, csv, null, now, now));
                }))
                .then();
    }

    private static String keyFor(String credentialConfigurationId) {
        return KEY_PREFIX + credentialConfigurationId;
    }

}
