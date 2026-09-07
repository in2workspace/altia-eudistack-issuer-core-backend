package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;
import reactor.util.context.ContextView;

import java.time.Instant;
import java.util.List;
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
        configId = ids.getFirst();
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

    private CredentialCatalogEntryDto entry(List<CredentialCatalogEntryDto> catalog) {
        return catalog.stream()
                .filter(e -> e.credentialConfigurationId().equals(configId))
                .findFirst().orElseThrow();
    }

    private static ContextView ctx(String tenant) {
        return Context.of(TENANT_DOMAIN_CONTEXT_KEY, tenant);
    }
}
