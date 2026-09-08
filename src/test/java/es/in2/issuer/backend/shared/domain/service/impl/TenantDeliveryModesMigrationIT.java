package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import reactor.util.context.Context;
import reactor.util.context.ContextView;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves the {@code V13__Add_delivery_modes_to_tenant_credential_profile.sql} migration
 * (AC-07, EC-06, EC-07, ES-08, NFR-S-169-05) against a real Postgres, driving Flyway by
 * hand rather than relying on the full application start-up.
 *
 * <p>{@link es.in2.issuer.backend.shared.infrastructure.config.TenantSchemaFlywayMigrator}
 * runs as an {@code ApplicationRunner} and migrates every schema in {@code tenant_registry}
 * (seeded by {@code tenant-registry-init.sql}, which includes {@code e2e-tenant-a/b}) all the
 * way to the latest version <em>before</em> any test method gets to run -- there is no window
 * left to seed legacy {@code tenant_config} data ahead of V13 on those schemas. Each test here
 * therefore creates its own, unregistered tenant schema and drives Flyway itself in two steps:
 * migrate to V12 first, seed the legacy fixture, then migrate again (now applying V13).
 *
 * <p>{@code TenantAwareConnectionFactoryDecorator} sets {@code search_path} from the reactive
 * context by regex-validated tenant name alone (no {@code tenant_registry} lookup), so an
 * unregistered schema works exactly like a registered one for {@code databaseClient} and the
 * repository/service beans used to seed and assert.
 */
class TenantDeliveryModesMigrationIT extends PostgresIntegrationBase {

    @Autowired private FlywayProperties flywayProperties;
    @Autowired private R2dbcProperties r2dbcProperties;
    @Autowired private TenantCredentialProfileRepository repository;
    @Autowired private TenantCredentialProfileService service;
    @Autowired private CredentialProfileRegistry registry;

    private String configId() {
        List<String> ids = List.copyOf(registry.getAllProfiles().keySet());
        assertThat(ids).as("registry must expose at least one credential profile").isNotEmpty();
        return ids.getFirst();
    }

    /**
     * AC-07 / NFR-S-169-05: a legacy {@code issuer.delivery.modes.<ccid>} value lands, intact,
     * as the migrated row's {@code delivery_modes} -- and the service reports exactly those
     * modes as configured, so no tenant's effective eligibility changes because of the migration.
     */
    @Test
    void migration_backfillsLegacyDeliveryModes_losslessly() {
        String tenant = "migration-lossless";
        String configId = configId();
        createSchemaAndMigrateTo(tenant, "12");
        seedEnabledProfile(tenant, configId);
        seedLegacyDeliveryModes(tenant, configId, "email,ui");

        migrateFully(tenant);

        List<TenantCredentialProfile> rows = repository.findAllByEnabledTrue()
                .collectList().contextWrite(ctx(tenant)).block();
        assertThat(rows).extracting(TenantCredentialProfile::deliveryModes).containsExactly("email,ui");

        Set<DeliveryMode> configured = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(tenant)).block();
        assertThat(configured).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
    }

    /**
     * EC-06: re-running the migration (Flyway itself, not just the SQL in isolation) is a
     * no-op -- it must not fail, and it must not revert a delivery-modes value the tenant
     * admin changed after the initial migration ran.
     */
    @Test
    void migration_appliedTwice_isIdempotentAndDoesNotOverwriteLaterConfig() {
        String tenant = "migration-idempotent";
        String configId = configId();
        createSchemaAndMigrateTo(tenant, "12");
        seedEnabledProfile(tenant, configId);
        seedLegacyDeliveryModes(tenant, configId, "email");

        migrateFully(tenant);

        // Admin reconfigures after the migration -- this must survive a repeat migrate().
        service.updateCatalog(Set.of(configId), Map.of(configId, EnumSet.of(DeliveryMode.UI)))
                .contextWrite(ctx(tenant)).block();

        migrateFully(tenant);

        Set<DeliveryMode> configured = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(tenant)).block();
        assertThat(configured).containsExactly(DeliveryMode.UI);
    }

    /**
     * EC-07: a legacy key for a credential_configuration_id that isn't an enabled row in this
     * tenant's catalog is discarded without failing the migration -- the type isn't emissible
     * there, so there is nothing to backfill it onto.
     */
    @Test
    void migration_discardsLegacyKeyForANotEnabledType() {
        String tenant = "migration-not-enabled";
        String configId = configId();
        createSchemaAndMigrateTo(tenant, "12");
        // Satisfies the guard's "catalog not empty" clause; unrelated to the discarded key below.
        seedEnabledProfile(tenant, configId);
        seedLegacyDeliveryModes(tenant, "some.type.never.enabled", "email");

        migrateFully(tenant);

        List<TenantCredentialProfile> rows = repository.findAllByEnabledTrue()
                .collectList().contextWrite(ctx(tenant)).block();
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactly(configId);
        assertThat(rows.getFirst().deliveryModes()).isNull();
    }

    /**
     * ES-08: a legacy value that cannot be parsed as a CSV of known delivery modes fails the
     * migration outright (fail-closed) rather than silently dropping or truncating it.
     */
    @Test
    void migration_failsClosedOnUnmigratableLegacyValue() {
        String tenant = "migration-bad-value";
        String configId = configId();
        createSchemaAndMigrateTo(tenant, "12");
        seedEnabledProfile(tenant, configId);
        seedLegacyDeliveryModes(tenant, configId, "carrier-pigeon");

        assertThatThrownBy(() -> migrateFully(tenant)).isInstanceOf(FlywayException.class);
    }

    /**
     * ES-08: an empty catalog (no enabled rows at all) with a legacy key present has nowhere
     * lossless to land the backfill -- "empty catalog" would otherwise mean "everything
     * enabled" under the pre-EUD-72 semantics, so the migration refuses rather than guess.
     */
    @Test
    void migration_failsClosedOnEmptyCatalogWithLegacyKeys() {
        String tenant = "migration-empty-catalog";
        String configId = configId();
        createSchemaAndMigrateTo(tenant, "12");
        seedLegacyDeliveryModes(tenant, configId, "email");
        // Deliberately no seedEnabledProfile call: the catalog is empty.

        assertThatThrownBy(() -> migrateFully(tenant)).isInstanceOf(FlywayException.class);
    }

    // ---- helpers ---------------------------------------------------------------

    private String schemaOf(String tenant) {
        return tenant + SCHEMA_SUFFIX;
    }

    private void createSchemaAndMigrateTo(String tenant, String targetVersion) {
        String schema = schemaOf(tenant);
        databaseClient.sql("CREATE SCHEMA IF NOT EXISTS \"" + schema + "\"").then().block();
        flyway(schema).target(targetVersion).load().migrate();
    }

    private void migrateFully(String tenant) {
        flyway(schemaOf(tenant)).load().migrate();
    }

    private FluentConfiguration flyway(String schema) {
        return Flyway.configure()
                .dataSource(flywayProperties.getUrl(), r2dbcProperties.getUsername(), r2dbcProperties.getPassword())
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history");
    }

    private void seedEnabledProfile(String tenant, String configId) {
        String schema = schemaOf(tenant);
        databaseClient.sql("INSERT INTO \"" + schema + "\".tenant_credential_profile "
                        + "(credential_configuration_id, enabled) VALUES (:configId, true)")
                .bind("configId", configId)
                .then().block();
    }

    private void seedLegacyDeliveryModes(String tenant, String configId, String csv) {
        String schema = schemaOf(tenant);
        databaseClient.sql("INSERT INTO \"" + schema + "\".tenant_config "
                        + "(config_key, config_value) VALUES (:key, :value)")
                .bind("key", "issuer.delivery.modes." + configId)
                .bind("value", csv)
                .then().block();
    }

    private static ContextView ctx(String tenant) {
        return Context.of(TENANT_DOMAIN_CONTEXT_KEY, tenant);
    }
}
