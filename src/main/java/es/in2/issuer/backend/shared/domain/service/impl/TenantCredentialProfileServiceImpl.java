package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
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
    private final TransactionalOperator transactionalOperator;
    private final R2dbcEntityTemplate r2dbcEntityTemplate;
    private final Cache<String, Set<String>> cache;

    public TenantCredentialProfileServiceImpl(
            TenantCredentialProfileRepository repository,
            CredentialProfileRegistry registry,
            TransactionalOperator transactionalOperator,
            R2dbcEntityTemplate r2dbcEntityTemplate) {
        this.repository = repository;
        this.registry = registry;
        this.transactionalOperator = transactionalOperator;
        this.r2dbcEntityTemplate = r2dbcEntityTemplate;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(CACHE_TTL)
                .maximumSize(100)
                .build();
    }

    @Override
    public Mono<Set<String>> getEnabledConfigurationIds() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");
            Set<String> cached = cache.getIfPresent(tenant);
            if (cached != null) {
                return Mono.just(cached);
            }

            return repository.findAllByEnabledTrue()
                    .map(TenantCredentialProfile::credentialConfigurationId)
                    .collect(Collectors.toSet())
                    .doOnNext(ids -> {
                        cache.put(tenant, ids);
                        log.debug("Loaded {} enabled credential profiles for tenant '{}'", ids.size(), tenant);
                    });
        });
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

    @Override
    public Mono<List<CredentialCatalogEntryDto>> getCatalog() {
        return Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx);
            return getEnabledConfigurationIds()
                    .map(enabledIds -> registry.getAllProfiles().entrySet().stream()
                            .map(entry -> new CredentialCatalogEntryDto(
                                    entry.getKey(),
                                    resolveDisplayName(entry.getValue()),
                                    enabledIds.contains(entry.getKey()),
                                    List.of(),
                                    List.of()))
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
    public Mono<Set<DeliveryMode>> findConfiguredDeliveryModes(String credentialConfigurationId) {
        // TODO(EUD-169 task 7): wire to the per-tenant cache once it moves to
        // Cache<String, Map<String, Set<DeliveryMode>>> (AD-8). Stub keeps the module
        // compiling between task 5 (port) and task 7 (real cache-backed implementation).
        return Mono.just(Set.of());
    }

    @Override
    public Mono<Void> updateCatalog(Set<String> enabledConfigurationIds, Map<String, Set<DeliveryMode>> deliveryModesByConfigurationId) {
        Set<String> knownIds = registry.getAllProfiles().keySet();
        Set<String> unknown = enabledConfigurationIds.stream()
                .filter(id -> !knownIds.contains(id))
                .collect(Collectors.toSet());
        if (!unknown.isEmpty()) {
            return Mono.error(new UnknownCredentialConfigurationException(
                    "Unknown credential configuration id(s): " + unknown));
        }

        return Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx);
            Instant now = Instant.now();
            List<TenantCredentialProfile> rows = enabledConfigurationIds.stream()
                    .map(id -> new TenantCredentialProfile(null, id, true, now, now, null))
                    .toList();

            Mono<Void> write = repository.deleteAll()
                    .thenMany(Flux.fromIterable(rows).concatMap(r2dbcEntityTemplate::insert))
                    .then();

            return transactionalOperator.transactional(write)
                    .doOnSuccess(v -> {
                        cache.invalidate(tenant);
                        log.info("Credential catalog updated for tenant '{}': {} type(s) enabled",
                                tenant, enabledConfigurationIds.size());
                    });
        });
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
