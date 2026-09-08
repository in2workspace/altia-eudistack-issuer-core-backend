package es.in2.issuer.backend.shared.domain.model.dto.credential;

import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HolderCnfJsonTest {

    // A real P-256 public point (same fixture as HolderKeyTest): Nimbus validates x/y are actually
    // on the declared curve, so an arbitrary placeholder string is not a valid fixture here.
    private static final String VALID_EC_X = "jIoYu_tVQYeSX_WAXLz219rFkqGV6c4FTb4_cQdOaQg";
    private static final String VALID_EC_Y = "BBkUW2sUZX2kW7keQ-qZV3PCKCLOZesPpszoNGciDL4";

    @Test
    void readValidated_nullOrBlank_returnsEmptyMap() {
        assertThat(HolderCnfJson.readValidated(null)).isEmpty();
        assertThat(HolderCnfJson.readValidated("  ")).isEmpty();
    }

    @Test
    void readValidated_wellFormedJwk_returnsCanonicalCnf() {
        String json = "{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + VALID_EC_X + "\",\"y\":\"" + VALID_EC_Y + "\"}}";

        Map<String, Object> cnf = HolderCnfJson.readValidated(json);

        assertThat(cnf).containsOnlyKeys("jwk");
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
        assertThat(jwk).isEqualTo(Map.of("kty", "EC", "crv", "P-256", "x", VALID_EC_X, "y", VALID_EC_Y));
    }

    /**
     * TD-13's own evidence: {@code HolderCnfJson.read("{\"jwk\":\"str\"}")} deserializes to
     * {@code {jwk=str}} -- a non-null, non-empty map that {@code read} alone would happily return,
     * even though {@code jwk} is a {@code String}, not an object. {@code readValidated} closes this
     * by running the same node through {@link es.in2.issuer.backend.issuance.domain.model.HolderKey},
     * which requires {@code jwk} to be a JSON object.
     */
    @Test
    void readValidated_jwkIsAStringNotAnObject_throwsInvalidHolderKey() {
        assertThatThrownBy(() -> HolderCnfJson.readValidated("{\"jwk\":\"str\"}"))
                .isInstanceOf(InvalidHolderKeyException.class);
    }

    @Test
    void readValidated_jwkWithMalformedCoordinates_throwsInvalidHolderKey() {
        String json = "{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"!!!not-base64url!!!\",\"y\":\"y-coord\"}}";

        assertThatThrownBy(() -> HolderCnfJson.readValidated(json))
                .isInstanceOf(InvalidHolderKeyException.class);
    }

    @Test
    void readValidated_unsupportedKeyType_throwsInvalidHolderKey() {
        String json = "{\"jwk\":{\"kty\":\"oct\",\"k\":\"c2VjcmV0\"}}";

        assertThatThrownBy(() -> HolderCnfJson.readValidated(json))
                .isInstanceOf(InvalidHolderKeyException.class);
    }

    /**
     * TD-15. A present-but-empty JSON object is NOT the same as an absent column: absent means
     * "this type never populates cnf, fall back to the key-proof binding" (legitimate, returns
     * {@code Map.of()}), while {@code "{}"} means someone wrote a row with no {@code jwk} member at
     * all -- silently returning an empty map here would mean a signed credential loses its cnf
     * binding without anyone noticing. Must fail closed the same as any other malformed shape.
     */
    @Test
    void readValidated_presentButEmptyObject_throwsInvalidHolderKeyRatherThanTreatingItAsAbsent() {
        assertThatThrownBy(() -> HolderCnfJson.readValidated("{}"))
                .isInstanceOf(InvalidHolderKeyException.class);
    }

    /**
     * TD-15. A stored literal {@code "null"} is not the same as an absent column (that case is
     * {@code proc.getHolderCnf() == null}, caught by the top-level null/blank guard) -- it is a
     * present-but-corrupted value. Jackson deserializes the JSON literal {@code null} to a Java
     * {@code null}, not an empty map, so it must still fail closed with a clear
     * {@code InvalidHolderKeyException} (same as {@code "{}"}), not a raw
     * {@code NullPointerException} from dereferencing it.
     */
    @Test
    void readValidated_literalJsonNullString_failsClosedRatherThanThrowingNpe() {
        assertThatThrownBy(() -> HolderCnfJson.readValidated("null"))
                .isInstanceOf(InvalidHolderKeyException.class);
    }
}
