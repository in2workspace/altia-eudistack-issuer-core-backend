package es.in2.issuer.backend.shared.infrastructure.persistence;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class IssuanceMapperTest {

    @Test
    void shouldMapEntityToDomainRoundTrippingEveryField() {
        UUID issuanceId = UUID.randomUUID();
        Timestamp validFrom = new Timestamp(1_700_000_000_000L);
        Timestamp validUntil = new Timestamp(1_800_000_000_000L);
        Instant deliveryAttemptedAt = Instant.ofEpochSecond(1_750_000_000L);
        Instant createdAt = Instant.ofEpochSecond(1_600_000_000L);
        Instant updatedAt = Instant.ofEpochSecond(1_650_000_000L);

        IssuanceEntity entity = IssuanceEntity.builder()
                .issuanceId(issuanceId)
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{\"foo\":\"bar\"}")
                .credentialStatus(CredentialStatusEnum.ISSUED)
                .organizationIdentifier("VATEU-B12345678")
                .subject("subject-value")
                .credentialType("LEARCredential")
                .validFrom(validFrom)
                .validUntil(validUntil)
                .email("test@in2.es")
                .delivery("EMAIL")
                .credentialOfferRefreshToken("refresh-token")
                .signedCredential("signed-jwt")
                .deliveryAttemptedAt(deliveryAttemptedAt)
                .holderCnf("{\"jwk\":{\"kty\":\"EC\"}}")
                .version(3L)
                .createdAt(createdAt)
                .updatedAt(updatedAt)
                .createdBy("system")
                .updatedBy("admin")
                .build();

        Issuance domain = IssuanceMapper.toDomain(entity);

        assertThat(domain.getIssuanceId()).isEqualTo(issuanceId);
        assertThat(domain.getCredentialFormat()).isEqualTo("jwt_vc_json");
        assertThat(domain.getCredentialDataSet()).isEqualTo("{\"foo\":\"bar\"}");
        assertThat(domain.getCredentialStatus()).isEqualTo(CredentialStatusEnum.ISSUED);
        assertThat(domain.getOrganizationIdentifier()).isEqualTo("VATEU-B12345678");
        assertThat(domain.getSubject()).isEqualTo("subject-value");
        assertThat(domain.getCredentialType()).isEqualTo("LEARCredential");
        assertThat(domain.getValidFrom()).isEqualTo(validFrom);
        assertThat(domain.getValidUntil()).isEqualTo(validUntil);
        assertThat(domain.getEmail()).isEqualTo("test@in2.es");
        assertThat(domain.getDelivery()).isEqualTo("EMAIL");
        assertThat(domain.getCredentialOfferRefreshToken()).isEqualTo("refresh-token");
        assertThat(domain.getSignedCredential()).isEqualTo("signed-jwt");
        assertThat(domain.getDeliveryAttemptedAt()).isEqualTo(deliveryAttemptedAt);
        assertThat(domain.getHolderCnf()).isEqualTo("{\"jwk\":{\"kty\":\"EC\"}}");
        assertThat(domain.getVersion()).isEqualTo(3L);
        assertThat(domain.getCreatedAt()).isEqualTo(createdAt);
        assertThat(domain.getUpdatedAt()).isEqualTo(updatedAt);
        assertThat(domain.getCreatedBy()).isEqualTo("system");
        assertThat(domain.getUpdatedBy()).isEqualTo("admin");
    }

    @Test
    void shouldMapDomainToEntityRoundTrippingEveryField() {
        UUID issuanceId = UUID.randomUUID();
        Timestamp validFrom = new Timestamp(1_700_000_000_000L);
        Timestamp validUntil = new Timestamp(1_800_000_000_000L);
        Instant deliveryAttemptedAt = Instant.ofEpochSecond(1_750_000_000L);
        Instant createdAt = Instant.ofEpochSecond(1_600_000_000L);
        Instant updatedAt = Instant.ofEpochSecond(1_650_000_000L);

        Issuance domain = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{\"foo\":\"bar\"}")
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .organizationIdentifier("VATEU-B12345678")
                .subject("subject-value")
                .credentialType("LEARCredential")
                .validFrom(validFrom)
                .validUntil(validUntil)
                .email("test@in2.es")
                .delivery("EMAIL")
                .credentialOfferRefreshToken("refresh-token")
                .signedCredential("signed-jwt")
                .deliveryAttemptedAt(deliveryAttemptedAt)
                .holderCnf("{\"jwk\":{\"kty\":\"EC\"}}")
                .version(7L)
                .createdAt(createdAt)
                .updatedAt(updatedAt)
                .createdBy("system")
                .updatedBy("admin")
                .build();

        IssuanceEntity entity = IssuanceMapper.toEntity(domain);

        assertThat(entity.getIssuanceId()).isEqualTo(issuanceId);
        assertThat(entity.getCredentialFormat()).isEqualTo("jwt_vc_json");
        assertThat(entity.getCredentialDataSet()).isEqualTo("{\"foo\":\"bar\"}");
        assertThat(entity.getCredentialStatus()).isEqualTo(CredentialStatusEnum.DRAFT);
        assertThat(entity.getOrganizationIdentifier()).isEqualTo("VATEU-B12345678");
        assertThat(entity.getSubject()).isEqualTo("subject-value");
        assertThat(entity.getCredentialType()).isEqualTo("LEARCredential");
        assertThat(entity.getValidFrom()).isEqualTo(validFrom);
        assertThat(entity.getValidUntil()).isEqualTo(validUntil);
        assertThat(entity.getEmail()).isEqualTo("test@in2.es");
        assertThat(entity.getDelivery()).isEqualTo("EMAIL");
        assertThat(entity.getCredentialOfferRefreshToken()).isEqualTo("refresh-token");
        assertThat(entity.getSignedCredential()).isEqualTo("signed-jwt");
        assertThat(entity.getDeliveryAttemptedAt()).isEqualTo(deliveryAttemptedAt);
        assertThat(entity.getHolderCnf()).isEqualTo("{\"jwk\":{\"kty\":\"EC\"}}");
        assertThat(entity.getVersion()).isEqualTo(7L);
        assertThat(entity.getCreatedAt()).isEqualTo(createdAt);
        assertThat(entity.getUpdatedAt()).isEqualTo(updatedAt);
        assertThat(entity.getCreatedBy()).isEqualTo("system");
        assertThat(entity.getUpdatedBy()).isEqualTo("admin");
    }

    @Test
    void shouldReturnNullWhenMappingNullEntityToDomain() {
        assertThat(IssuanceMapper.toDomain(null)).isNull();
    }

    @Test
    void shouldReturnNullWhenMappingNullDomainToEntity() {
        assertThat(IssuanceMapper.toEntity(null)).isNull();
    }
}
