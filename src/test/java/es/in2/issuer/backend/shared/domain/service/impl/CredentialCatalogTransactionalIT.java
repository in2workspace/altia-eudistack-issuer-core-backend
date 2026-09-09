package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.CredentialConfigurationNotEnabledException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;
import reactor.util.context.ContextView;

import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves that reactive transactions ({@link TransactionalOperator}) work correctly on
 * top of the schema-per-tenant {@code TenantAwareConnectionFactoryDecorator} (EUD-72,
 * risk R-2). This is the first reactive transaction exercised in the Issuer, so it
 * verifies four things end-to-end against a real Postgres:
 *
 * <ol>
 *   <li>a committed {@code updateCatalog} lands in the current tenant's schema and is
 *       readable back;</li>
 *   <li>writes are isolated between tenants (search_path honored inside the transaction);</li>
 *   <li>an error mid-transaction rolls back the {@code deleteAll}, leaving the prior
 *       state intact — the failure mode that would otherwise wipe the tenant catalog and
 *       leave it unable to issue;</li>
 *   <li>re-applying the same set is idempotent (EC-03).</li>
 * </ol>
 */
class CredentialCatalogTransactionalIT extends PostgresIntegrationBase {

    private static final String TENANT_A = "e2e-tenant-a";
    private static final String TENANT_B = "e2e-tenant-b";

    // Second real profile fixture (TD-2/TD-4): a distinct, unbound credential type so
    // ES-04/ES-10 can exercise a genuinely mixed multi-type payload against a real
    // Postgres instead of only against the one bound fixture that used to be alone on
    // this classpath (src/test/resources/credentials/profiles).
    private static final String SECOND_CONFIG_ID = "gx.labelcredential.w3c.2";

    @Autowired private TenantCredentialProfileService service;
    @Autowired private TenantCredentialProfileRepository repository;
    @Autowired private TransactionalOperator transactionalOperator;
    @Autowired private R2dbcEntityTemplate r2dbcEntityTemplate;
    @Autowired private CredentialProfileRegistry registry;

    private String configId;

    @BeforeEach
    void resetTenants() {
        List<String> ids = List.copyOf(registry.getAllProfiles().keySet());
        assertThat(ids).as("registry must expose at least one credential profile").isNotEmpty();
        assertThat(registry.getByConfigurationId(SECOND_CONFIG_ID))
                .as("registry must expose the second fixture (%s) used by ES-04/ES-10 multi-type tests", SECOND_CONFIG_ID)
                .isNotNull();
        // Exclude SECOND_CONFIG_ID explicitly rather than trusting registry iteration order --
        // it must never equal configId (Set.of(configId, SECOND_CONFIG_ID) below would throw
        // IllegalArgumentException: duplicate element if it did).
        configId = ids.stream().filter(id -> !id.equals(SECOND_CONFIG_ID)).findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "registry must expose a profile distinct from " + SECOND_CONFIG_ID));
        // Clear both tenant schemas (empty set → deleteAll → nothing enabled).
        service.updateCatalog(Set.of()).contextWrite(ctx(TENANT_A)).block();
        service.updateCatalog(Set.of()).contextWrite(ctx(TENANT_B)).block();
    }

    @Test
    void updateCatalog_committedWrite_isReadableBackFromTenantSchema() {
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactly(configId);

        List<CredentialCatalogEntryDto> catalog =
                service.getCatalog().contextWrite(ctx(TENANT_A)).block();
        assertThat(catalog).isNotNull();
        assertThat(entry(catalog).enabled()).isTrue();
    }

    @Test
    void updateCatalog_isolatedBetweenTenants() {
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();
        // TENANT_B left empty by resetTenants().

        List<TenantCredentialProfile> rowsA =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        List<TenantCredentialProfile> rowsB =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_B)).block();

        assertThat(rowsA).hasSize(1);
        assertThat(rowsB).isEmpty();

        // B never configured → nothing enabled → the catalog read is a 404, not an empty view.
        StepVerifier.create(service.getCatalog().contextWrite(ctx(TENANT_B)))
                .expectError(CredentialCatalogNotConfiguredException.class)
                .verify();
    }

    /**
     * EC-03: saving the same selection twice must be a no-op seen from outside. The write
     * is delete-then-insert, so the risk is duplicated rows rather than a changed verdict;
     * both the stored rows and the catalog projection are asserted.
     */
    @Test
    void updateCatalog_appliedTwiceWithSameSet_isIdempotent() {
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();
        List<CredentialCatalogEntryDto> afterFirst =
                service.getCatalog().contextWrite(ctx(TENANT_A)).block();

        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();
        List<CredentialCatalogEntryDto> afterSecond =
                service.getCatalog().contextWrite(ctx(TENANT_A)).block();

        // deleteAll precedes the inserts inside the transaction → exactly one row, not two.
        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactly(configId);
        assertThat(afterFirst).isNotNull();
        assertThat(afterSecond).isEqualTo(afterFirst);
    }

    @Test
    void transactionalWrite_rollsBackOnError_leavingPreviousStateIntact() {
        // Committed baseline for tenant A.
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        Instant now = Instant.now();
        Mono<Void> failingTx = transactionalOperator.transactional(
                repository.deleteAll()
                        .then(r2dbcEntityTemplate.insert(
                                new TenantCredentialProfile(null, configId, true, now, now, null)).then())
                        .then(Mono.<Void>error(new RuntimeException("boom")))
        ).contextWrite(ctx(TENANT_A));

        StepVerifier.create(failingTx).expectError(RuntimeException.class).verify();

        // deleteAll must have been rolled back → baseline row still present.
        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactly(configId);
    }

    /**
     * EC-01: a write that omits a type's delivery-modes entry entirely preserves whatever
     * is already stored -- the engine-side COALESCE in the UPSERT (task 6), not a
     * read-modify-write.
     */
    @Test
    void updateCatalog_omittingModesField_preservesStoredModes() {
        service.updateCatalog(Set.of(configId), Map.of(configId, EnumSet.of(DeliveryMode.EMAIL)))
                .contextWrite(ctx(TENANT_A)).block();

        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        Set<DeliveryMode> configured = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(TENANT_A)).block();
        assertThat(configured).containsExactly(DeliveryMode.EMAIL);
    }

    /**
     * EC-02: disabling a type drops its row -- and with it, its stored delivery modes.
     * Re-enabling it afterward must reopen it to the schema ceiling (AC-03), not resurrect
     * the modes it had before being disabled.
     */
    @Test
    void disablingType_dropsItsRowAndDeliveryModes() {
        service.updateCatalog(Set.of(configId), Map.of(configId, EnumSet.of(DeliveryMode.EMAIL)))
                .contextWrite(ctx(TENANT_A)).block();

        service.updateCatalog(Set.of()).contextWrite(ctx(TENANT_A)).block();
        List<TenantCredentialProfile> afterDisable =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(afterDisable).isEmpty();

        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();
        Set<DeliveryMode> configuredAfterReEnable = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(TENANT_A)).block();
        assertThat(configuredAfterReEnable).isEmpty();
    }

    /**
     * EC-03 (with modes): reapplying the same delivery-modes configuration twice is a
     * no-op -- one row, same canonical value, no error.
     */
    @Test
    void updateCatalog_reappliedWithSameModes_isIdempotent() {
        Map<String, Set<DeliveryMode>> modes = Map.of(configId, EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

        service.updateCatalog(Set.of(configId), modes).contextWrite(ctx(TENANT_A)).block();
        service.updateCatalog(Set.of(configId), modes).contextWrite(ctx(TENANT_A)).block();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).hasSize(1);
        assertThat(rows.getFirst().deliveryModes()).isEqualTo("email,ui");
    }

    /**
     * ES-04: two overlapping writes for the same tenant, fired concurrently (Flux.merge
     * subscribes to both eagerly, unlike sequential blocking), must leave a single
     * coherent row -- never a duplicate or partially-written one -- regardless of which
     * one's delivery-modes value ultimately wins the race.
     */
    @Test
    void concurrentUpdates_sameTenant_leaveNoDuplicateRowsAndPreservesUntouchedType() {
        // Seed both types enabled; SECOND_CONFIG_ID starts with modes already configured.
        service.updateCatalog(Set.of(configId, SECOND_CONFIG_ID),
                        Map.of(SECOND_CONFIG_ID, EnumSet.of(DeliveryMode.UI)))
                .contextWrite(ctx(TENANT_A)).block();

        // Neither concurrent write below declares modes for SECOND_CONFIG_ID (ES-04: "el
        // sistema MUST NOT perder los modos de entrega de los tipos que ninguna de las dos
        // declaró") -- its stored modes must survive both, regardless of interleaving.
        Mono<Void> writeDeclaringModes = service.updateCatalog(
                        Set.of(configId, SECOND_CONFIG_ID), Map.of(configId, EnumSet.of(DeliveryMode.EMAIL)))
                .contextWrite(ctx(TENANT_A));
        Mono<Void> writePreservingModes = service.updateCatalog(Set.of(configId, SECOND_CONFIG_ID))
                .contextWrite(ctx(TENANT_A));

        Flux.merge(writeDeclaringModes, writePreservingModes).blockLast();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).hasSize(2);
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactlyInAnyOrder(configId, SECOND_CONFIG_ID);
        assertThat(rows).filteredOn(r -> r.credentialConfigurationId().equals(SECOND_CONFIG_ID))
                .extracting(TenantCredentialProfile::deliveryModes)
                .containsExactly("ui");
    }

    /**
     * AC-06 / NFR-S-169-04: delivery modes stored for the same credential_configuration_id
     * never leak between tenants.
     */
    @Test
    void deliveryModes_areIsolatedBetweenTenants() {
        service.updateCatalog(Set.of(configId), Map.of(configId, EnumSet.of(DeliveryMode.EMAIL)))
                .contextWrite(ctx(TENANT_A)).block();
        service.updateCatalog(Set.of(configId), Map.of(configId, EnumSet.of(DeliveryMode.UI)))
                .contextWrite(ctx(TENANT_B)).block();

        Set<DeliveryMode> configuredA = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(TENANT_A)).block();
        Set<DeliveryMode> configuredB = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(TENANT_B)).block();

        assertThat(configuredA).containsExactly(DeliveryMode.EMAIL);
        assertThat(configuredB).containsExactly(DeliveryMode.UI);
    }

    /**
     * AC-08: the retired parallel module's route no longer exists post-cutover. Bound
     * directly to the server port (not the {@code /issuer}-prefixed helper from the base
     * class, which is specific to the apiclient/oauth flows) since this path was never
     * under that prefix.
     */
    @Test
    void oldDeliveryConfigRoute_noLongerExists_returns404() {
        WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port)
                .build()
                .get().uri("/api/v1/backoffice/delivery-config/" + configId)
                .exchange()
                .expectStatus().isNotFound();
    }

    /**
     * ES-10, against a real DB: a declared credential_configuration_id known to the
     * registry but not currently enabled for the tenant is rejected atomically -- and
     * because the write is a plain {@code UPDATE} (AD-14), there is structurally nothing
     * to roll back: the row count stays at zero, the type is not silently enabled as a
     * side effect of the failed PATCH.
     */
    @Test
    void updateDeliveryModes_ccidNotEnabled_rejectsAndCreatesNoRow() {
        StepVerifier.create(service.updateDeliveryModes(Map.of(configId, Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(ctx(TENANT_A)))
                .expectError(CredentialConfigurationNotEnabledException.class)
                .verify();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).isEmpty();
    }

    /**
     * ES-10 (TD-4, now closed against a real DB): mixing one already-enabled id with a
     * distinct, known-but-not-enabled one rejects the whole operation atomically --
     * "el sistema MUST NOT persistir ninguna parte de la petición, tampoco los modos de
     * los tipos que sí estaban habilitados". {@code configId} is enabled and declares a
     * change; {@code SECOND_CONFIG_ID} is known to the registry but never enabled for
     * this tenant. Complements the unit-level, mocked coverage of the same clause
     * ({@code TenantCredentialProfileServiceImplTest#updateDeliveryModes_oneIdNotEnabled_rejectsAndWritesNothingElse}).
     */
    @Test
    void updateDeliveryModes_mixedEnabledAndNotEnabled_rejectsAtomicallyWritingNothing() {
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        StepVerifier.create(service.updateDeliveryModes(Map.of(
                                configId, Set.of(DeliveryMode.EMAIL),
                                SECOND_CONFIG_ID, Set.of(DeliveryMode.UI)))
                        .contextWrite(ctx(TENANT_A)))
                .expectError(CredentialConfigurationNotEnabledException.class)
                .verify();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).hasSize(1);
        assertThat(rows.getFirst().credentialConfigurationId()).isEqualTo(configId);
        assertThat(rows.getFirst().deliveryModes())
                .as("the enabled type's own declared change must not land either -- the whole operation aborted")
                .isNull();
    }

    /**
     * EC-10, against a real DB: a successful PATCH on an already-enabled catalog leaves
     * the set of enabled types and the row count exactly as they were -- the point
     * adjustment is a pure {@code UPDATE} on the existing row, never an insert or a
     * prune.
     */
    @Test
    void updateDeliveryModes_success_leavesEnabledSetAndRowCountUnchanged() {
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        service.updateDeliveryModes(Map.of(configId, Set.of(DeliveryMode.EMAIL, DeliveryMode.UI)))
                .contextWrite(ctx(TENANT_A)).block();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactly(configId);
        assertThat(rows.getFirst().deliveryModes()).isEqualTo("email,ui");
    }

    private CredentialCatalogEntryDto entry(List<CredentialCatalogEntryDto> catalog) {
        return catalog.stream()
                .filter(e -> e.credentialConfigurationId().equals(configId))
                .findFirst().orElseThrow();
    }

    private static ContextView ctx(String tenant) {
        return Context.of(TENANT_DOMAIN_CONTEXT_KEY, tenant);
    }
}
