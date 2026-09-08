package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Real Postgres coverage for the {@code holder_cnf} column round-trip (EUD-168 TD-12).
 *
 * <p>{@code IssuanceMapperTest} already proves the Java-side field copy (domain &lt;-&gt;
 * entity) with a literal fixture, but that closes only the *mapper* failure class. It says
 * nothing about the *DDL/codec* class -- a tenant schema missing the {@code V12} migration, a
 * renamed column, or an R2DBC codec issue -- whose symptom is identical: {@code holder_cnf}
 * comes back {@code NULL}, which is exactly how the {@code 0731beb6} regression (EUDISTACK-650
 * merge dropping the field in the new mapper) went undetected until manual smoke testing.
 *
 * <p>Fixture is a real P-256 public point (Nimbus validates the curve, not just JSON shape),
 * the same one {@code HolderKeyTest} uses, so the assertion covers value fidelity and not only
 * field presence.
 */
class HolderCnfPersistenceIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";

    private static final String VALID_EC_X = "jIoYu_tVQYeSX_WAXLz219rFkqGV6c4FTb4_cQdOaQg";
    private static final String VALID_EC_Y = "BBkUW2sUZX2kW7keQ-qZV3PCKCLOZesPpszoNGciDL4";
    private static final String HOLDER_CNF_JSON =
            "{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + VALID_EC_X + "\",\"y\":\"" + VALID_EC_Y + "\"}}";

    @Autowired
    private IssuancePort issuancePort;

    private Issuance seed(CredentialStatusEnum status) {
        Issuance issuance = Issuance.builder()
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{}")
                .credentialStatus(status)
                .organizationIdentifier("ORG-A")
                .credentialType("learcredential.machine.w3c.3")
                .email("holder@example.com")
                .delivery("ui")
                .holderCnf(HOLDER_CNF_JSON)
                .build();
        return issuancePort.insert(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
    }

    private Issuance reread(UUID issuanceId) {
        return issuancePort.findByIssuanceId(issuanceId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
    }

    @Test
    void insertThenReread_holderCnfSurvivesTheRoundTripExactly() {
        Issuance inserted = seed(CredentialStatusEnum.DRAFT);

        Issuance reread = reread(inserted.getIssuanceId());

        assertThat(reread.getHolderCnf()).isEqualTo(HOLDER_CNF_JSON);
    }

    @Test
    void readModifySave_holderCnfSurvivesAnUnrelatedFieldUpdate() {
        Issuance inserted = seed(CredentialStatusEnum.DRAFT);

        Issuance toUpdate = reread(inserted.getIssuanceId());
        toUpdate.setCredentialStatus(CredentialStatusEnum.ISSUED);
        issuancePort.save(toUpdate)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();

        Issuance afterSave = reread(inserted.getIssuanceId());

        assertThat(afterSave.getCredentialStatus()).isEqualTo(CredentialStatusEnum.ISSUED);
        assertThat(afterSave.getHolderCnf()).isEqualTo(HOLDER_CNF_JSON);
    }

    @Test
    void insertThenReread_holderCnfIsNullForATypeThatNeverSetsIt() {
        Issuance issuance = Issuance.builder()
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{}")
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .organizationIdentifier("ORG-A")
                .credentialType("gx.labelcredential.w3c.2")
                .email("holder@example.com")
                .delivery("email")
                .build();
        Issuance inserted = issuancePort.insert(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();

        Issuance reread = reread(inserted.getIssuanceId());

        assertThat(reread.getHolderCnf()).isNull();
    }
}
