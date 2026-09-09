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
     */
    @Modifying
    @Query("""
           DELETE FROM tenant_credential_profile
           WHERE credential_configuration_id NOT IN (:ids)
           """)
    Mono<Integer> deleteAllByCredentialConfigurationIdNotIn(Set<String> ids);

    /**
     * Updates only the {@code delivery_modes} column of a single, already-enabled row --
     * an {@code UPDATE}, never an {@code UPSERT} (AD-14): a statement that cannot insert
     * cannot enable a type as a side effect. Returns {@code 0} when the id is unknown to
     * this tenant's schema or currently disabled, which the caller (service layer) turns
     * into {@code CredentialConfigurationNotEnabledException} (ES-10).
     */
    @Modifying
    @Query("""
           UPDATE tenant_credential_profile
              SET delivery_modes = :deliveryModes,
                  updated_at     = :updatedAt
            WHERE credential_configuration_id = :credentialConfigurationId
              AND enabled = true
           """)
    Mono<Integer> updateDeliveryModesIfEnabled(String credentialConfigurationId, String deliveryModes, Instant updatedAt);

}
