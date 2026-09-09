package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.CredentialConfigurationNotEnabledException;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
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
    @Mock private SchemaDeliveryCeiling schemaDeliveryCeiling;
    @Mock private TransactionalOperator transactionalOperator;

    private TenantCredentialProfileServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new TenantCredentialProfileServiceImpl(repository, registry, schemaDeliveryCeiling, transactionalOperator);
        // Pass-through transaction: return the wrapped Mono unchanged.
        when(transactionalOperator.transactional(any(Mono.class)))
                .thenAnswer(inv -> inv.getArgument(0));
        // Default ceiling: everything eligible (unbound type). Tests that care about a
        // narrower ceiling override this for their specific credential_configuration_id.
        when(schemaDeliveryCeiling.resolveEligibleModes(anyString())).thenReturn(EnumSet.allOf(DeliveryMode.class));
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

    /**
     * AC-01: each entry carries both the eligible modes (stored ∩ ceiling) and the schema
     * ceiling on its own, both in canonical (alphabetical) order.
     */
    @Test
    void getCatalog_enrichesWithDeliveryModesAndSchemaCeiling() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A", "email")));
        when(schemaDeliveryCeiling.resolveEligibleModes("A"))
                .thenReturn(EnumSet.allOf(DeliveryMode.class));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> {
                    CredentialCatalogEntryDto a = entry(list, "A");
                    assertThat(a.deliveryModes()).containsExactly("email");
                    assertThat(a.schemaEligibleModes()).containsExactly("direct", "email", "ui");
                })
                .verifyComplete();
    }

    /**
     * EC-05: a type disabled for the tenant still reports its schema ceiling, so the admin
     * UI can paint the full row.
     */
    @Test
    void getCatalog_disabledEntry_stillReportsSchemaCeiling() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "A"),
                "B", profile("B", "B")));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A")));
        when(schemaDeliveryCeiling.resolveEligibleModes("B"))
                .thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> {
                    CredentialCatalogEntryDto b = entry(list, "B");
                    assertThat(b.enabled()).isFalse();
                    assertThat(b.schemaEligibleModes()).containsExactly("email", "ui");
                })
                .verifyComplete();
    }

    /**
     * AC-03: a type with no explicit configuration is open to the entire schema ceiling.
     */
    @Test
    void getCatalog_noExplicitConfig_offersEntireCeiling() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A", null)));
        when(schemaDeliveryCeiling.resolveEligibleModes("A"))
                .thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> assertThat(entry(list, "A").deliveryModes()).containsExactly("email", "ui"))
                .verifyComplete();
    }

    /**
     * EC-04: a type whose stored configuration happens to equal the ceiling is
     * observably identical to one with no configuration at all (AC-03) -- and stays
     * that way even if the ceiling narrows later, unlike the unconfigured case.
     */
    @Test
    void getCatalog_configuredModesEqualCeiling_indistinguishableFromUnconfigured() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A", "email,ui")));
        when(schemaDeliveryCeiling.resolveEligibleModes("A"))
                .thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> assertThat(entry(list, "A").deliveryModes()).containsExactly("email", "ui"))
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

    @Test
    void findConfiguredDeliveryModes_notConfigured_returnsEmptySet() {
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A", null)));

        StepVerifier.create(service.findConfiguredDeliveryModes("A")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(modes -> assertThat(modes).isEmpty())
                .verifyComplete();
    }

    @Test
    void findConfiguredDeliveryModes_configured_returnsStoredModes() {
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A", "direct,email")));

        StepVerifier.create(service.findConfiguredDeliveryModes("A")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(modes -> assertThat(modes).containsExactlyInAnyOrder(DeliveryMode.DIRECT, DeliveryMode.EMAIL))
                .verifyComplete();
    }

    /**
     * Security review (F6): a type that is not enabled at all (absent from
     * findAllByEnabledTrue()) must not be collapsed into the same empty Set as "enabled but
     * unconfigured" (see the passing test above) -- DeliveryEligibilityResolver would default
     * that to the schema ceiling, letting an unenabled type inherit eligibility instead of
     * being refused.
     */
    @Test
    void findConfiguredDeliveryModes_notEnabledAtAll_errorsWithNotEnabled() {
        when(repository.findAllByEnabledTrue()).thenReturn(Flux.just(row("A", "direct,email")));

        StepVerifier.create(service.findConfiguredDeliveryModes("unknown-or-not-enabled")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(CredentialConfigurationNotEnabledException.class)
                .verify();
    }

    /**
     * Security review (EUD-169): unlike getEnabledConfigurationIds() (tolerant, read by public
     * metadata), this feeds an issuance-time security decision and must fail closed rather than
     * silently resolve against the "unknown"/public schema.
     */
    @Test
    void findConfiguredDeliveryModes_noTenantInContext_badRequest() {
        StepVerifier.create(service.findConfiguredDeliveryModes("A"))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .verify();

        verify(repository, never()).findAllByEnabledTrue();
    }

    /**
     * AC-06: the per-tenant cache keys on the tenant, so two tenants never see each
     * other's enabled ids even though the repository mock is shared.
     */
    @Test
    void twoTenants_haveIndependentEnabledIds() {
        when(repository.findAllByEnabledTrue())
                .thenReturn(Flux.just(row("A")))
                .thenReturn(Flux.just(row("B")));

        StepVerifier.create(service.getEnabledConfigurationIds()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "tenant-1")))
                .assertNext(ids -> assertThat(ids).containsExactly("A"))
                .verifyComplete();
        StepVerifier.create(service.getEnabledConfigurationIds()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "tenant-2")))
                .assertNext(ids -> assertThat(ids).containsExactly("B"))
                .verifyComplete();

        verify(repository, times(2)).findAllByEnabledTrue();
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
        verify(repository, never()).upsert(anyString(), anyBoolean(), any(), any());
    }

    @Test
    void updateCatalog_noTenantInContext_badRequest() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));

        StepVerifier.create(service.updateCatalog(Set.of("A")))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .verify();

        verify(repository, never()).deleteAll();
        verify(repository, never()).upsert(anyString(), anyBoolean(), any(), any());
    }

    /**
     * ES-03: delivery modes declared for a ccid outside enabledConfigurationIds are
     * rejected with InvalidDeliveryConfigException, and nothing is persisted.
     */
    @Test
    void updateCatalog_mapKeyNotInEnabledIds_rejectsWithoutPersisting() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B")));

        StepVerifier.create(service.updateCatalog(Set.of("A"), Map.of("B", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(InvalidDeliveryConfigException.class)
                .verify();

        verify(repository, never()).deleteAll();
        verify(repository, never()).upsert(anyString(), anyBoolean(), any(), any());
    }

    /**
     * AC-04, migrated from the retired TenantDeliveryConfigServiceImplTest
     * (setEligibleModes_directOnBoundType_rejectsWithoutTouchingTheRepository, R-9):
     * a mode outside the schema ceiling is rejected before any write -- not even the
     * other declared type persists.
     */
    @Test
    void updateCatalog_directOnBoundType_rejectsWithoutPersistingAnyDeclaredType() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B")));
        doThrow(new DeliveryModeNotEligibleException("direct not eligible for A"))
                .when(schemaDeliveryCeiling).validateWithinCeiling(eq("A"), any());

        StepVerifier.create(service.updateCatalog(
                        Set.of("A", "B"),
                        Map.of("A", Set.of(DeliveryMode.DIRECT), "B", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(DeliveryModeNotEligibleException.class)
                .verify();

        verify(repository, never()).upsert(anyString(), anyBoolean(), any(), any());
    }

    /**
     * EC-08 + migrated from setEligibleModes_withinCeiling_persistsNormally (R-9):
     * a set within the ceiling persists, canonicalized (sorted, deduplicated) before
     * it reaches the repository.
     */
    @Test
    void updateCatalog_withinCeiling_persistsCanonicalizedModes() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.upsert(eq("A"), eq(true), eq("email,ui"), any())).thenReturn(Mono.just(1));
        when(repository.deleteAllByCredentialConfigurationIdNotIn(Set.of("A"))).thenReturn(Mono.just(0));

        StepVerifier.create(service.updateCatalog(Set.of("A"), Map.of("A", Set.of(DeliveryMode.UI, DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository, times(1)).upsert(eq("A"), eq(true), eq("email,ui"), any());
    }

    /**
     * EC-03, migrated from setEligibleModes_reappliedWithSameValue_isIdempotent (R-9):
     * reapplying the same update twice succeeds both times with the same persisted value.
     */
    @Test
    void updateCatalog_reappliedWithSameValue_isIdempotent() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.upsert(eq("A"), eq(true), eq("email"), any())).thenReturn(Mono.just(1));
        when(repository.deleteAllByCredentialConfigurationIdNotIn(Set.of("A"))).thenReturn(Mono.just(0));

        StepVerifier.create(service.updateCatalog(Set.of("A"), Map.of("A", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();
        StepVerifier.create(service.updateCatalog(Set.of("A"), Map.of("A", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository, times(2)).upsert(eq("A"), eq(true), eq("email"), any());
    }

    /**
     * EC-01: a ccid enabled but absent from the delivery-modes map preserves whatever is
     * already stored -- signalled to the repository as a null value for COALESCE to keep.
     */
    @Test
    void updateCatalog_omittingModesMapEntry_preservesExistingStoredModes() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.upsert(eq("A"), eq(true), isNull(), any())).thenReturn(Mono.just(1));
        when(repository.deleteAllByCredentialConfigurationIdNotIn(Set.of("A"))).thenReturn(Mono.just(0));

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository, times(1)).upsert(eq("A"), eq(true), isNull(), any());
    }

    /**
     * EC-02: disabling a type prunes its row (and with it, its stored delivery modes).
     */
    @Test
    void updateCatalog_disablingType_prunesRow() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B")));
        when(repository.upsert(eq("A"), eq(true), isNull(), any())).thenReturn(Mono.just(1));
        when(repository.deleteAllByCredentialConfigurationIdNotIn(Set.of("A"))).thenReturn(Mono.just(1));

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository).deleteAllByCredentialConfigurationIdNotIn(Set.of("A"));
    }

    /**
     * The admin API rejects an empty set (400, see {@code UpdateCredentialCatalogRequest});
     * at service level it remains the reset primitive and leaves nothing enabled.
     */
    @Test
    void updateCatalog_emptySet_deletesAllNoUpsert() {
        when(repository.deleteAll()).thenReturn(Mono.empty());

        StepVerifier.create(service.updateCatalog(Set.of())
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository).deleteAll();
        verify(repository, never()).upsert(anyString(), anyBoolean(), any(), any());
        verify(repository, never()).deleteAllByCredentialConfigurationIdNotIn(any());
    }

    @Test
    void updateCatalog_success_invalidatesCache() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.upsert(eq("A"), eq(true), isNull(), any())).thenReturn(Mono.just(1));
        when(repository.deleteAllByCredentialConfigurationIdNotIn(Set.of("A"))).thenReturn(Mono.just(0));
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
        when(repository.upsert(eq("A"), eq(true), isNull(), any()))
                .thenReturn(Mono.error(new RuntimeException("db down")));
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

    // ---- updateDeliveryModes (PATCH, AC-11) ------------------------------------

    /**
     * AC-11: writes exactly the declared credential_configuration_ids, each normalized
     * to canonical CSV before it reaches the repository.
     */
    @Test
    void updateDeliveryModes_declaredIds_writesEachOne() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B")));
        when(repository.updateDeliveryModesIfEnabled(eq("A"), eq("email"), any())).thenReturn(Mono.just(1));
        when(repository.updateDeliveryModesIfEnabled(eq("B"), eq("email,ui"), any())).thenReturn(Mono.just(1));

        StepVerifier.create(service.updateDeliveryModes(
                        Map.of("A", Set.of(DeliveryMode.EMAIL), "B", Set.of(DeliveryMode.UI, DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository, times(1)).updateDeliveryModesIfEnabled(eq("A"), eq("email"), any());
        verify(repository, times(1)).updateDeliveryModesIfEnabled(eq("B"), eq("email,ui"), any());
    }

    /**
     * EC-10: this operation never inserts or deletes rows -- only the two declared
     * updates are the repository, no upsert/delete/prune call is ever made.
     */
    @Test
    void updateDeliveryModes_neverCreatesOrDeletesRows() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.updateDeliveryModesIfEnabled(eq("A"), eq("email"), any())).thenReturn(Mono.just(1));

        StepVerifier.create(service.updateDeliveryModes(Map.of("A", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository, never()).upsert(anyString(), anyBoolean(), any(), any());
        verify(repository, never()).deleteAllByCredentialConfigurationIdNotIn(any());
        verify(repository, never()).deleteAll();
    }

    /**
     * EC-11: reapplying the same request twice, and again with the modes declared in a
     * different order with repeats, is idempotent and normalizes identically each time.
     */
    @Test
    void updateDeliveryModes_reappliedWithSameValueInAnyOrder_isIdempotent() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(repository.updateDeliveryModesIfEnabled(eq("A"), eq("email,ui"), any())).thenReturn(Mono.just(1));

        StepVerifier.create(service.updateDeliveryModes(Map.of("A", Set.of(DeliveryMode.EMAIL, DeliveryMode.UI)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();
        StepVerifier.create(service.updateDeliveryModes(Map.of("A", Set.of(DeliveryMode.UI, DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(repository, times(2)).updateDeliveryModesIfEnabled(eq("A"), eq("email,ui"), any());
    }

    /**
     * ES-10: a rowsAffected == 0 for any declared id (not currently enabled) aborts the
     * whole operation -- not even the ids that were enabled get written, verified here
     * by asserting the second id's update is never attempted (sequential, alphabetical
     * order, W-7) once the first one fails.
     */
    @Test
    void updateDeliveryModes_oneIdNotEnabled_rejectsAndWritesNothingElse() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B")));
        when(repository.updateDeliveryModesIfEnabled(eq("A"), anyString(), any())).thenReturn(Mono.just(0));

        StepVerifier.create(service.updateDeliveryModes(
                        Map.of("A", Set.of(DeliveryMode.EMAIL), "B", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(CredentialConfigurationNotEnabledException.class)
                .verify();

        verify(repository, never()).updateDeliveryModesIfEnabled(eq("B"), anyString(), any());
    }

    /**
     * Order of validation (AD-14): an id unknown to the registry must fail with
     * UnknownCredentialConfigurationException (→ 400) before SchemaDeliveryCeiling is
     * ever consulted -- inverting the order would surface as an unhandled 500 instead.
     */
    @Test
    void updateDeliveryModes_unknownId_failsFastBeforeCeilingCheck() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));

        StepVerifier.create(service.updateDeliveryModes(Map.of("UNKNOWN", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(UnknownCredentialConfigurationException.class)
                .verify();

        verify(schemaDeliveryCeiling, never()).validateWithinCeiling(anyString(), any());
        verify(repository, never()).updateDeliveryModesIfEnabled(anyString(), anyString(), any());
    }

    /**
     * AC-04, via the point-adjustment path: a mode outside the schema ceiling is rejected
     * before any write, exactly as the PUT rejects it.
     */
    @Test
    void updateDeliveryModes_directOnBoundType_rejectsWithoutWriting() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        doThrow(new DeliveryModeNotEligibleException("direct not eligible for A"))
                .when(schemaDeliveryCeiling).validateWithinCeiling(eq("A"), any());

        StepVerifier.create(service.updateDeliveryModes(Map.of("A", Set.of(DeliveryMode.DIRECT)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(DeliveryModeNotEligibleException.class)
                .verify();

        verify(repository, never()).updateDeliveryModesIfEnabled(anyString(), anyString(), any());
    }

    // ---- helpers --------------------------------------------------------------

    private static CredentialCatalogEntryDto entry(List<CredentialCatalogEntryDto> list, String id) {
        return list.stream().filter(e -> e.credentialConfigurationId().equals(id)).findFirst().orElseThrow();
    }

    private static TenantCredentialProfile row(String configId) {
        return row(configId, null);
    }

    private static TenantCredentialProfile row(String configId, String deliveryModes) {
        return new TenantCredentialProfile(UUID.randomUUID(), configId, true, Instant.now(), Instant.now(), deliveryModes);
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
