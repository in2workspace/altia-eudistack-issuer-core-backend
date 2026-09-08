package es.in2.issuer.backend.shared.infrastructure.persistence;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;

/**
 * Hand-written mapper between the domain {@link Issuance} and its R2DBC persistence
 * counterpart {@link IssuanceEntity}. Round-trips every field, including {@code version}
 * and the auditing fields, so Spring Data R2DBC's optimistic locking and auditing behave
 * exactly as before the domain/infrastructure split (EUDISTACK-650 / H-05).
 */
public final class IssuanceMapper {

    private IssuanceMapper() {
    }

    public static Issuance toDomain(IssuanceEntity entity) {
        if (entity == null) {
            return null;
        }
        return Issuance.builder()
                .issuanceId(entity.getIssuanceId())
                .credentialFormat(entity.getCredentialFormat())
                .credentialDataSet(entity.getCredentialDataSet())
                .credentialStatus(entity.getCredentialStatus())
                .organizationIdentifier(entity.getOrganizationIdentifier())
                .subject(entity.getSubject())
                .credentialType(entity.getCredentialType())
                .validFrom(entity.getValidFrom())
                .validUntil(entity.getValidUntil())
                .email(entity.getEmail())
                .delivery(entity.getDelivery())
                .credentialOfferRefreshToken(entity.getCredentialOfferRefreshToken())
                .signedCredential(entity.getSignedCredential())
                .deliveryAttemptedAt(entity.getDeliveryAttemptedAt())
                .holderCnf(entity.getHolderCnf())
                .version(entity.getVersion())
                .createdAt(entity.getCreatedAt())
                .updatedAt(entity.getUpdatedAt())
                .createdBy(entity.getCreatedBy())
                .updatedBy(entity.getUpdatedBy())
                .build();
    }

    public static IssuanceEntity toEntity(Issuance issuance) {
        if (issuance == null) {
            return null;
        }
        return IssuanceEntity.builder()
                .issuanceId(issuance.getIssuanceId())
                .credentialFormat(issuance.getCredentialFormat())
                .credentialDataSet(issuance.getCredentialDataSet())
                .credentialStatus(issuance.getCredentialStatus())
                .organizationIdentifier(issuance.getOrganizationIdentifier())
                .subject(issuance.getSubject())
                .credentialType(issuance.getCredentialType())
                .validFrom(issuance.getValidFrom())
                .validUntil(issuance.getValidUntil())
                .email(issuance.getEmail())
                .delivery(issuance.getDelivery())
                .credentialOfferRefreshToken(issuance.getCredentialOfferRefreshToken())
                .signedCredential(issuance.getSignedCredential())
                .deliveryAttemptedAt(issuance.getDeliveryAttemptedAt())
                .holderCnf(issuance.getHolderCnf())
                .version(issuance.getVersion())
                .createdAt(issuance.getCreatedAt())
                .updatedAt(issuance.getUpdatedAt())
                .createdBy(issuance.getCreatedBy())
                .updatedBy(issuance.getUpdatedBy())
                .build();
    }
}
