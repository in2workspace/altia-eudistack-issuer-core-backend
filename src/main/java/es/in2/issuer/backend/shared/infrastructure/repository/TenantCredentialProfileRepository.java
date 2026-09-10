package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Repository
public interface TenantCredentialProfileRepository extends ReactiveCrudRepository<TenantCredentialProfile, UUID> {

    Flux<TenantCredentialProfile> findAllByEnabledTrue();

    /**
     * Upserts one row by {@code credential_configuration_id}. A {@code null} deliveryModes
     * preserves whatever is already stored (EC-01) instead of clearing it -- the merge
     * happens in the engine ({@code COALESCE}), so there is no read-modify-write window
     * (W-1/W-2, {@code technical-design.md} §3.4.2).
     */
    @Modifying
    @Query("""
           INSERT INTO tenant_credential_profile (credential_configuration_id, enabled, delivery_modes, created_at, updated_at)
           VALUES (:credentialConfigurationId, :enabled, :deliveryModes, :updatedAt, :updatedAt)
           ON CONFLICT (credential_configuration_id) DO UPDATE
              SET enabled        = EXCLUDED.enabled,
                  delivery_modes = COALESCE(EXCLUDED.delivery_modes, tenant_credential_profile.delivery_modes),
                  updated_at     = EXCLUDED.updated_at
           """)
    Mono<Integer> upsert(String credentialConfigurationId, boolean enabled, String deliveryModes, Instant updatedAt);

    /**
     * Prunes every row whose {@code credential_configuration_id} is not in {@code ids} --
     * a type no longer enabled loses both its enablement and its stored delivery modes
     * (EC-02).
     *
     * <p>Guards {@code ids.isEmpty()} explicitly (code review, TD-8): today's only caller
     * ({@code TenantCredentialProfileServiceImpl#updateCatalog}) already routes an empty
     * set to {@code deleteAll()} instead, so this is unreachable in production -- but a
     * future direct caller passing an empty set would otherwise hit an engine-level
     * {@code NOT IN ()}, whose behavior differs by driver/engine. No-op (0 rows) is the
     * correct, unambiguous result for "nothing to keep, nothing declared to prune against".
     */
    default Mono<Integer> deleteAllByCredentialConfigurationIdNotIn(Set<String> ids) {
        return ids.isEmpty() ? Mono.just(0) : deleteAllNotIn(ids);
    }

    @Modifying
    @Query("""
           DELETE FROM tenant_credential_profile
           WHERE credential_configuration_id NOT IN (:ids)
           """)
    Mono<Integer> deleteAllNotIn(Set<String> ids);

}
