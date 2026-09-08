package es.in2.issuer.backend.shared.infrastructure.persistence;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import jakarta.annotation.Nullable;
import lombok.*;
import org.springframework.data.annotation.*;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

/**
 * R2DBC persistence model for the {@code issuance} table. Mirrors the domain
 * {@link es.in2.issuer.backend.shared.domain.model.entities.Issuance} field-for-field;
 * {@link IssuanceMapper} converts between the two at the adapter boundary
 * (EUDISTACK-650 / H-05 — domain must not depend on org.springframework.data).
 */
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Table("issuance")
public class IssuanceEntity {
    @Id
    @Column("issuance_id")
    private UUID issuanceId;

    @Column("credential_format")
    private String credentialFormat;

    @Column("credential_data_set")
    private String credentialDataSet;

    @Column("credential_status")
    private CredentialStatusEnum credentialStatus;

    @Column("organization_identifier")
    private String organizationIdentifier;

    @Column("subject")
    @Nullable
    private String subject;

    @Column("credential_type")
    private String credentialType;

    @Column("valid_from")
    private Timestamp validFrom;

    @Column("valid_until")
    private Timestamp validUntil;

    @Column("email")
    private String email;

    @Column("delivery")
    private String delivery;

    @Column("credential_offer_refresh_token")
    private String credentialOfferRefreshToken;

    @Column("signed_credential")
    @Nullable
    private String signedCredential;

    @Column("delivery_attempted_at")
    @Nullable
    private Instant deliveryAttemptedAt;

    // EUD-168 AD-8/AD-9: cnf claim for the two machine LEARCredential types exempt from
    // ADR-110, sourced from the issuance request's holder_key and read back by the Wallet
    // leg's Credential Endpoint request, where no key proof will ever arrive to replace it.
    // Null for every other credential type (V12 migration).
    @Column("holder_cnf")
    @Nullable
    private String holderCnf;

    // Optimistic locking (V11, SD-04/EUD-225): every write to this row follows
    // find -> validateTransition -> mutate -> save with no version check in between.
    // Spring Data R2DBC manages this field automatically on save() -- a stale write now
    // fails fast with OptimisticLockingFailureException instead of silently overwriting a
    // concurrent writer's change (see IssuanceServiceImpl.updateIssuanceStatusToRevoked for
    // the reconciliation this enables). IssuanceMapper round-trips this field so the value
    // Spring Data reads back on save() is always the one last read from the row.
    @Version
    @Column("version")
    private Long version;

    // --- Auditing fields (R2DBC auditing will fill these) ---
    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    @LastModifiedDate
    @Column("updated_at")
    private Instant updatedAt;

    @CreatedBy
    @Column("created_by")
    private String createdBy;

    @LastModifiedBy
    @Column("updated_by")
    private String updatedBy;
    // --------------------------------------------------------
}
