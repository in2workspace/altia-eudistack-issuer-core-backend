package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TenantCredentialProfileServiceImplTest {

    private static final String TENANT = "demo";

    @Mock private TenantCredentialProfileRepository repository;
    @Mock private CredentialProfileRegistry registry;
    @Mock private TransactionalOperator transactionalOperator;
    @Mock private R2dbcEntityTemplate r2dbcEntityTemplate;

    private TenantCredentialProfileServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new TenantCredentialProfileServiceImpl(repository, registry, transactionalOperator, r2dbcEntityTemplate);
        // Pass-through transaction: return the wrapped Mono unchanged.
        when(transactionalOperator.transactional(any(Mono.class)))
                .thenAnswer(inv -> inv.getArgument(0));
        // insert echoes the entity back as a Mono. Match the entity overload explicitly
        // (R2dbcEntityTemplate.insert is overloaded with insert(Class<T>)).
        when(r2dbcEntityTemplate.insert(any(TenantCredentialProfile.class)))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));
    }

    // ---- getCatalog -----------------------------------------------------------

    @Test
    void getCatalog_emptyTable_notConfigured() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "Profile A"),
                "B", profile("B", null)));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.empty());

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(CredentialCatalogNotConfiguredException.class)
                .verify();
    }

    /**
     * Stored ids that no longer exist in the registry leave every entry disabled, which is
     * indistinguishable from "never configured" for the admin UI → same 404.
     */
    @Test
    void getCatalog_storedIdsUnknownToRegistry_notConfigured() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("RETIRED")));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(CredentialCatalogNotConfiguredException.class)
                .verify();
    }

    @Test
    void getCatalog_withEnabledSubset_flagsPerTenant() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "A"),
                "B", profile("B", "B"),
                "C", profile("C", "C")));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A"), row("C")));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> {
                    assertThat(entry(list, "A").enabled()).isTrue();
                    assertThat(entry(list, "B").enabled()).isFalse();
                    assertThat(entry(list, "C").enabled()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void getCatalog_displayName_fallsBackToConfigurationId() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "Profile A"),
                "B", profile("B", null)));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A"), row("B")));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> {
                    assertThat(entry(list, "A").displayName()).isEqualTo("Profile A");
                    assertThat(entry(list, "B").displayName()).isEqualTo("B");
                })
                .verifyComplete();
    }

    // ---- read side: no rows ⇒ nothing enabled ---------------------------------

    @Test
    void isProfileAllowed_emptyTable_isFalse() {
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.empty());

        StepVerifier.create(service.isProfileAllowed("A")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    void getAvailableProfiles_emptyTable_isEmpty() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.empty());

        StepVerifier.create(service.getAvailableProfiles()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(profiles -> assertThat(profiles).isEmpty())
                .verifyComplete();
    }

    @Test
    void getAvailableProfiles_withEnabledSubset_returnsOnlyEnabled() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "A"),
                "B", profile("B", "B")));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("B")));

        StepVerifier.create(service.getAvailableProfiles()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(profiles -> assertThat(profiles).containsOnlyKeys("B"))
                .verifyComplete();
    }

    @Test
    void getCatalog_noTenantInContext_badRequest() {
        StepVerifier.create(service.getCatalog())
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .verify();
    }

    // ---- updateCatalog --------------------------------------------------------

    @Test
    void updateCatalog_unknownId_failsFastWithoutWriting() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));

        StepVerifier.create(service.updateCatalog(Set.of("UNKNOWN"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(UnknownCredentialConfigurationException.class)
                .verify();

        verify(repository, never()).deleteAll();
        verify(r2dbcEntityTemplate, never()).insert(any(TenantCredentialProfile.class));
    }

    @Test
    void updateCatalog_noTenantInContext_badRequest() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));

        StepVerifier.create(service.updateCatalog(Set.of("A")))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .verify();

        verify(repository, never()).deleteAll();
    }

    @Test
    void updateCatalog_validSubset_deletesThenInserts() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B")));
        when(repository.deleteAll()).thenReturn(Mono.empty());

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository).deleteAll();
        verify(r2dbcEntityTemplate, times(1)).insert(any(TenantCredentialProfile.class));
    }

    /**
     * The admin API rejects an empty set (400, see {@code UpdateCredentialCatalogRequest});
     * at service level it remains the reset primitive and leaves nothing enabled.
     */
    @Test
    void updateCatalog_emptySet_deletesAllNoInsert() {
        when(repository.deleteAll()).thenReturn(Mono.empty());

        StepVerifier.create(service.updateCatalog(Set.of())
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository).deleteAll();
        verify(r2dbcEntityTemplate, never()).insert(any(TenantCredentialProfile.class));
    }

    @Test
    void updateCatalog_success_invalidatesCache() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.deleteAll()).thenReturn(Mono.empty());
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A")));

        // Prime the cache for TENANT.
        service.getEnabledConfigurationIds()
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
        // Successful write must invalidate it.
        service.updateCatalog(Set.of("A"))
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
        // Reading again must hit the repository once more (cache was invalidated).
        service.getEnabledConfigurationIds()
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();

        verify(repository, times(2)).findAllByEnabledTrue();
    }

    @Test
    void updateCatalog_writeFails_doesNotInvalidateCache() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.deleteAll()).thenReturn(Mono.error(new RuntimeException("db down")));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A")));

        // Prime the cache.
        service.getEnabledConfigurationIds()
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
        // Failing write must NOT invalidate the cache.
        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(RuntimeException.class)
                .verify();
        // Cache still warm → repository not queried again.
        service.getEnabledConfigurationIds()
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();

        verify(repository, times(1)).findAllByEnabledTrue();
    }

    // ---- helpers --------------------------------------------------------------

    private static CredentialCatalogEntryDto entry(List<CredentialCatalogEntryDto> list, String id) {
        return list.stream().filter(e -> e.credentialConfigurationId().equals(id)).findFirst().orElseThrow();
    }

    private static TenantCredentialProfile row(String configId) {
        return new TenantCredentialProfile(UUID.randomUUID(), configId, true, Instant.now(), Instant.now(), null);
    }

    private static CredentialProfile profile(String id, String displayName) {
        var builder = CredentialProfile.builder().credentialConfigurationId(id);
        if (displayName != null) {
            builder.credentialMetadata(CredentialProfile.CredentialMetadata.builder()
                    .display(List.of(CredentialProfile.DisplayInfo.builder().name(displayName).build()))
                    .build());
        }
        return builder.build();
    }
}
