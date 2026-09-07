package es.in2.issuer.backend.shared.domain.model.entities;

import jakarta.annotation.Nullable;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import lombok.*;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

/**
 * Domain model for a credential issuance. Framework-free by design (EUDISTACK-650 / H-05):
 * persistence mapping (columns, optimistic-locking version, auditing) lives in the R2DBC
 * adapter's {@code IssuanceEntity} + {@code IssuanceMapper}, reached only through
 * {@code IssuancePort}.
 */
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Issuance {
    private UUID issuanceId;

    private String credentialFormat;

    private String credentialDataSet;

    private CredentialStatusEnum credentialStatus;

    private String organizationIdentifier;

    @Nullable
    private String subject;

    private String credentialType;

    private Timestamp validFrom;

    private Timestamp validUntil;

    private String email;

    private String delivery;

    private String credentialOfferRefreshToken;

    @Nullable
    private String signedCredential;

    @Nullable
    private Instant deliveryAttemptedAt;

    // Holder confirmation claim supplied in the issuance request (EUD-168 AD-8), as JSON.
    // Only the credential types exempt from ADR-110 populate it: they declare no
    // proof_types_supported, so the Credential Endpoint receives no key proof and this row is
    // the only surviving source of the holder key by the time the credential is signed.
    @Nullable
    private String holderCnf;

    // Optimistic-concurrency version (V11, SD-04/EUD-225). Opaque to domain logic: callers
    // never compare or set it themselves, they just carry it through find -> mutate -> save
    // so the persistence adapter can detect a lost race (see IssuancePort / IssuanceR2dbcAdapter
    // for the Spring Data R2DBC mechanics this enables).
    private Long version;

    // --- Auditing fields (populated by the persistence adapter) ---
    private Instant createdAt;

    private Instant updatedAt;

    private String createdBy;

    private String updatedBy;
    // ----------------------------------------------------------------
}
