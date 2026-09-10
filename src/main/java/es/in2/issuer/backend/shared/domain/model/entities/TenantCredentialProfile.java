package es.in2.issuer.backend.shared.domain.model.entities;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("tenant_credential_profile")
public record TenantCredentialProfile(
        @Id
        UUID id,

        @Column("credential_configuration_id")
        String credentialConfigurationId,

        @Column("enabled")
        boolean enabled,

        @Column("created_at")
        Instant createdAt,

        @Column("updated_at")
        Instant updatedAt,

        @Column("delivery_modes")
        String deliveryModes
) {
}
