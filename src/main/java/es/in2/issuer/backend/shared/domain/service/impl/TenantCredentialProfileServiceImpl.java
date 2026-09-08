package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
public class TenantCredentialProfileServiceImpl implements TenantCredentialProfileService {

    private static final Duration CACHE_TTL = Duration.ofMinutes(5);

    private final TenantCredentialProfileRepository repository;
    private final CredentialProfileRegistry registry;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;
    private final TransactionalOperator transactionalOperator;
    private final Cache<String, Map<String, Set<DeliveryMode>>> cache;

    public TenantCredentialProfileServiceImpl(
            TenantCredentialProfileRepository repository,
            CredentialProfileRegistry registry,
            SchemaDeliveryCeiling schemaDeliveryCeiling,
            TransactionalOperator transactionalOperator) {
        this.repository = repository;
        this.registry = registry;
        this.schemaDeliveryCeiling = schemaDeliveryCeiling;
        this.transactionalOperator = transactionalOperator;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(CACHE_TTL)
                .maximumSize(100)
                .build();
    }

    @Override
    public Mono<Set<String>> getEnabledConfigurationIds() {
        return getTenantModesMap().map(Map::keySet);
    }

    @Override
    public Mono<Map<String, CredentialProfile>> getAvailableProfiles() {
        return getEnabledConfigurationIds()
                .map(enabledIds -> registry.getAllProfiles().entrySet().stream()
                        .filter(entry -> enabledIds.contains(entry.getKey()))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));
    }

    @Override
    public Mono<Boolean> isProfileAllowed(String credentialConfigurationId) {
        return getEnabledConfigurationIds()
                .map(enabledIds -> enabledIds.contains(credentialConfigurationId));
    }

    /**
     * Unlike {@link #getEnabledConfigurationIds()} (tolerant of a missing tenant --
     * {@link es.in2.issuer.backend.shared.domain.service.impl.CredentialIssuerMetadataServiceImpl}
     * reads it for public, unauthenticated metadata), this feeds a security decision
     * ({@link es.in2.issuer.backend.shared.domain.service.DeliveryEligibilityResolver} on the
     * issuance path) and must fail closed rather than silently resolve against {@code public}
     * schema (security review, EUD-169).
     */
    @Override
    public Mono<Set<DeliveryMode>> findConfiguredDeliveryModes(String credentialConfigurationId) {
        return Mono.deferContextual(ctx -> {
            requireTenant(ctx);
            return getTenantModesMap()
                    .map(modesMap -> modesMap.getOrDefault(credentialConfigurationId, Set.of()));
        });
    }

    @Override
    public Mono<List<CredentialCatalogEntryDto>> getCatalog() {
        return Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx);
            return getTenantModesMap()
                    .map(modesMap -> registry.getAllProfiles().entrySet().stream()
                            .map(entry -> toEntryDto(entry.getKey(), entry.getValue(), modesMap))
                            .sorted(Comparator.comparing(CredentialCatalogEntryDto::displayName))
                            .toList())
                    .flatMap(entries -> {
                        if (entries.stream().noneMatch(CredentialCatalogEntryDto::enabled)) {
                            return Mono.error(new CredentialCatalogNotConfiguredException(
                                    "No credential configuration enabled for tenant '" + tenant + "'"));
                        }
                        return Mono.just(entries);
                    });
        });
    }

    @Override
    public Mono<Void> updateCatalog(Set<String> enabledConfigurationIds, Map<String, Set<DeliveryMode>> deliveryModesByConfigurationId) {
        Mono<Void> validation = Mono.fromRunnable(() -> validateUpdateRequest(enabledConfigurationIds, deliveryModesByConfigurationId));

        return validation.then(Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx);
            Instant now = Instant.now();

            Mono<Void> write = enabledConfigurationIds.isEmpty()
                    ? repository.deleteAll()
                    : Flux.fromIterable(enabledConfigurationIds)
                            .concatMap(id -> repository.upsert(id, true, canonicalModesOrNull(id, deliveryModesByConfigurationId), now))
                            .then(repository.deleteAllByCredentialConfigurationIdNotIn(enabledConfigurationIds))
                            .then();

            return transactionalOperator.transactional(write)
                    .doOnSuccess(v -> {
                        cache.invalidate(tenant);
                        log.info("Credential catalog updated for tenant '{}': {} type(s) enabled",
                                tenant, enabledConfigurationIds.size());
                    });
        }));
    }

    /**
     * Validates, in this strict order, before any transaction opens: (1) every enabled id is
     * known to the registry -- must run before touching {@link SchemaDeliveryCeiling}, which
     * throws an unchecked, unhandled {@link IllegalStateException} (→ generic 500) for an
     * unknown id; (2) every id declaring delivery modes is among the enabled ids (ES-03); (3)
     * each declared set of modes is within that type's schema ceiling (AC-04 → 409).
     */
    private void validateUpdateRequest(Set<String> enabledConfigurationIds, Map<String, Set<DeliveryMode>> deliveryModesByConfigurationId) {
        Set<String> knownIds = registry.getAllProfiles().keySet();
        Set<String> unknown = enabledConfigurationIds.stream()
                .filter(id -> !knownIds.contains(id))
                .collect(Collectors.toSet());
        if (!unknown.isEmpty()) {
            throw new UnknownCredentialConfigurationException(
                    "Unknown credential configuration id(s): " + unknown);
        }

        Set<String> notEnabled = deliveryModesByConfigurationId.keySet().stream()
                .filter(id -> !enabledConfigurationIds.contains(id))
                .collect(Collectors.toSet());
        if (!notEnabled.isEmpty()) {
            throw new InvalidDeliveryConfigException(
                    "Delivery modes declared for credential configuration id(s) not enabled in this request: " + notEnabled);
        }

        deliveryModesByConfigurationId.forEach(schemaDeliveryCeiling::validateWithinCeiling);
    }

    private String canonicalModesOrNull(String credentialConfigurationId, Map<String, Set<DeliveryMode>> deliveryModesByConfigurationId) {
        Set<DeliveryMode> declared = deliveryModesByConfigurationId.get(credentialConfigurationId);
        return declared == null ? null : DeliveryMode.toCanonicalCsv(declared);
    }

    private CredentialCatalogEntryDto toEntryDto(String credentialConfigurationId, CredentialProfile profile, Map<String, Set<DeliveryMode>> modesMap) {
        Set<DeliveryMode> ceiling = schemaDeliveryCeiling.resolveEligibleModes(credentialConfigurationId);
        Set<DeliveryMode> stored = modesMap.getOrDefault(credentialConfigurationId, Set.of());
        Set<DeliveryMode> eligible = stored.isEmpty()
                ? ceiling
                : stored.stream().filter(ceiling::contains).collect(Collectors.toSet());

        return new CredentialCatalogEntryDto(
                credentialConfigurationId,
                resolveDisplayName(profile),
                modesMap.containsKey(credentialConfigurationId),
                sortedValues(eligible),
                sortedValues(ceiling));
    }

    /**
     * Loads (or reads from cache) the per-tenant map of enabled credential_configuration_id to
     * its configured delivery modes. A present key with an empty value means "enabled, but no
     * delivery modes explicitly configured" -- the sentinel that callers (this class'
     * {@link #getCatalog()}, and {@code DeliveryEligibilityResolver} via
     * {@link #findConfiguredDeliveryModes}) fall back to the schema ceiling for (AD-8); an
     * absent key means "not enabled". {@code keySet()} of this map is exactly the enabled ids.
     */
    private Mono<Map<String, Set<DeliveryMode>>> getTenantModesMap() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");
            Map<String, Set<DeliveryMode>> cached = cache.getIfPresent(tenant);
            if (cached != null) {
                return Mono.just(cached);
            }

            return repository.findAllByEnabledTrue()
                    .collect(Collectors.toMap(
                            TenantCredentialProfile::credentialConfigurationId,
                            row -> parseStoredModes(row.deliveryModes())))
                    .map(Map::copyOf)
                    .doOnNext(modesMap -> {
                        cache.put(tenant, modesMap);
                        log.debug("Loaded {} enabled credential profiles for tenant '{}'", modesMap.size(), tenant);
                    });
        });
    }

    private static Set<DeliveryMode> parseStoredModes(String csv) {
        return (csv == null || csv.isBlank()) ? Set.of() : Set.copyOf(DeliveryMode.parse(csv));
    }

    private static List<String> sortedValues(Set<DeliveryMode> modes) {
        return modes.stream().map(m -> m.value).sorted().toList();
    }

    /**
     * Resolves the tenant from the reactive context, rejecting when it is absent.
     * The admin catalog paths must never fall back to a default schema (unlike the
     * read side, which tolerates a missing tenant for public/system flows).
     */
    private String requireTenant(ContextView ctx) {
        String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
        if (tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tenant context not resolved");
        }
        return tenant;
    }

    private String resolveDisplayName(CredentialProfile profile) {
        CredentialProfile.CredentialMetadata metadata = profile.credentialMetadata();
        if (metadata != null && metadata.display() != null && !metadata.display().isEmpty()) {
            String name = metadata.display().getFirst().name();
            if (name != null && !name.isBlank()) {
                return name;
            }
        }
        return profile.credentialConfigurationId();
    }

}
