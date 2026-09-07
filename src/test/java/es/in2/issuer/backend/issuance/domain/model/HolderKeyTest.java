package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HolderKeyTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String raw) {
        try {
            return MAPPER.readTree(raw);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // A real P-256 public point: Nimbus validates x/y are actually on the declared curve, so an
    // arbitrary placeholder string is not a valid fixture here.
    private static final String VALID_EC_X = "jIoYu_tVQYeSX_WAXLz219rFkqGV6c4FTb4_cQdOaQg";
    private static final String VALID_EC_Y = "BBkUW2sUZX2kW7keQ-qZV3PCKCLOZesPpszoNGciDL4";

    @Test
    @SuppressWarnings("unchecked")
    void fromJson_withJwk_returnsCnfCarryingCanonicalJwkObject() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + VALID_EC_X + "\",\"y\":\"" + VALID_EC_Y + "\"}}");

        Map<String, Object> cnf = HolderKey.fromJson(node).cnf();

        assertEquals(1, cnf.size());
        Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
        assertEquals(Map.of("kty", "EC", "crv", "P-256", "x", VALID_EC_X, "y", VALID_EC_Y), jwk);
    }

    @Test
    void fromJson_withJavaNull_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(null));
    }

    @Test
    void fromJson_withNullNode_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(NullNode.getInstance()));
    }

    @Test
    void fromJson_withEmptyObject_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{}")));
    }

    @Test
    void fromJson_withNonObjectNode_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("\"just-a-string\"")));
    }

    @Test
    void fromJson_withJwkNotObject_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"jwk\":\"not-an-object\"}")));
    }

    @Test
    void fromJson_withEmptyJwkObject_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"jwk\":{}}")));
    }

    @ParameterizedTest(name = "Unsupported holder key #{index}: {0}")
    @MethodSource("unsupportedHolderKeyNodes")
    void fromJson_withUnsupportedHolderKey_throwsInvalidHolderKey(String description, JsonNode node) {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    private static Stream<Arguments> unsupportedHolderKeyNodes() {
        return Stream.of(
                Arguments.of("unrelated key", json("{\"foo\":\"bar\"}")),
                Arguments.of("kid only", json("{\"kid\":\"did:key:z6Mk#key-1\"}")),
                Arguments.of("x5c only", json("{\"x5c\":[\"MIIBcert1\",\"MIIBcert2\"]}"))
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void fromJson_withJwkAndAnIrrelevantSiblingField_usesTheJwkAndIgnoresTheSibling() {
        // Once kid/x5c stopped being recognized forms, a sibling field next to jwk is no longer a
        // competing claim to resolve -- just noise the caller sent, silently ignored.
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + VALID_EC_X + "\",\"y\":\"" + VALID_EC_Y
                + "\"},\"kid\":\"irrelevant\"}");

        Map<String, Object> cnf = HolderKey.fromJson(node).cnf();

        Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
        assertEquals(VALID_EC_X, jwk.get("x"));
    }

    // --- Nimbus JWK content validation (EUD-168 F1, S1) ---

    @ParameterizedTest(name = "Invalid JWK #{index}")
    @MethodSource("invalidJwkNodes")
    void fromJson_withInvalidJwk_throwsInvalidHolderKey(JsonNode node) {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    private static Stream<JsonNode> invalidJwkNodes() {
        return Stream.of(
                json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + VALID_EC_X
                        + "\",\"y\":\"" + VALID_EC_Y
                        + "\",\"d\":\"PtiOr4fsLlHZ2QdHKcO2HoslwwlEXka6_ksM1fSDTdg\"}}"),
                json("{\"jwk\":{\"kty\":\"oct\",\"k\":\"c2VjcmV0\"}}"),
                json("{\"jwk\":{\"kty\":\"unsupported\",\"x\":\"abc\"}}"),
                json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"secp256k1\",\"x\":\"abc\",\"y\":\"def\"}}"),
                json("{\"jwk\":{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}}")
        );
    }

    @Test
    void fromJson_withOversizedJwkNode_throwsInvalidHolderKey() {
        String oversizedCoordinate = "A".repeat(10_000);
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + oversizedCoordinate + "\",\"y\":\"def\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    // --- Allowlist narrowed to EC P-256 only (code-review F2a): DidKeyDerivation can only turn a
    // P-256 point into a did:key, so accepting a curve/kty it cannot handle here would let a
    // Nimbus-valid jwk through validation and then fail did:key derivation silently downstream. ---

    @Test
    void fromJson_withRsaKey_throwsInvalidHolderKey() {
        // A real-size RSA key, rejected purely for its kty -- not for size, unlike the undersized
        // case above.
        JsonNode node = json("{\"jwk\":{\"kty\":\"RSA\",\"n\":\"" + "s".repeat(342) + "\",\"e\":\"AQAB\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    @Test
    void fromJson_withOkpKey_throwsInvalidHolderKey() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    @Test
    void fromJson_withEcP384Curve_throwsInvalidHolderKey() {
        // A structurally valid, non-P-256 EC curve -- P-256 is the only one accepted, not "any EC
        // curve Nimbus recognizes".
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-384\","
                + "\"x\":\"2jCG5DmpbcqB4NBhngT8V1yr3ZapEvOr3EDRLPqQvSjHhpJZTGKzO51_TeR0aWje\","
                + "\"y\":\"pDT9YKuTQzR1DzZLU_gcxA3ubMFxRW-eZm-eZzDp9-Ie55mYRIzMR15Fq3JBz3JR\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    // --- Canonical serialization (code-review F1b/D2): the signed cnf must be built explicitly
    // from kty/crv/x/y, never trusting whatever other recognized-but-unwanted JWK members (x5u,
    // kid, alg, use...) the raw request happened to carry alongside a structurally valid key. ---

    @Test
    @SuppressWarnings("unchecked")
    void fromJson_withJwkCarryingUnrecognizedAndRecognizedExtraMembers_keepsOnlyTheFourCanonicalOnes() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + VALID_EC_X + "\",\"y\":\"" + VALID_EC_Y
                + "\",\"smuggled\":\"payload\",\"x5u\":\"http://169.254.169.254/latest/meta-data/\","
                + "\"kid\":\"<script>alert(1)</script>\",\"use\":\"sig\",\"alg\":\"ES256\"}}");

        Map<String, Object> jwk = (Map<String, Object>) HolderKey.fromJson(node).cnf().get("jwk");

        assertEquals(Map.of("kty", "EC", "crv", "P-256", "x", VALID_EC_X, "y", VALID_EC_Y), jwk);
        assertFalse(jwk.containsKey("smuggled"));
        assertFalse(jwk.containsKey("x5u"));
        assertFalse(jwk.containsKey("kid"));
        assertFalse(jwk.containsKey("use"));
        assertFalse(jwk.containsKey("alg"));
    }

    // --- Fixed-length coordinate re-encoding (code-review D1): Nimbus accepts a mathematically
    // valid point encoded with a non-canonical length (e.g. an extra leading zero byte, which
    // BigInteger.toByteArray() adds whenever the true value's high bit is set), but
    // DidKeyDerivation's fixed-32-byte array arithmetic cannot handle that and used to silently
    // fail into a fallback identifier. Fixture is a real generated P-256 point whose raw x
    // requires 33 bytes; y is already 32. ---

    @Test
    @SuppressWarnings("unchecked")
    void fromJson_withNonCanonicalLengthCoordinate_reEncodesToTheFixedCurveLength() {
        String nonCanonicalX = "AMOk-XIh19undc22JKlmKhjUipQFwtI9JkWF_dWHvLUl"; // 33 raw bytes
        String canonicalX = "w6T5ciHX26d1zbYkqWYqGNSKlAXC0j0mRYX91Ye8tSU"; // same value, 32 bytes
        String y = "L8HP4e9THGZ9Bft_RbYd8FIRM1eYUbDIrt29UyZrE4Q"; // already 32 bytes
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + nonCanonicalX + "\",\"y\":\"" + y + "\"}}");

        // Must not throw: Nimbus accepts this point as mathematically valid on the curve.
        Map<String, Object> jwk = (Map<String, Object>) HolderKey.fromJson(node).cnf().get("jwk");

        assertEquals(canonicalX, jwk.get("x"));
        assertEquals(32, java.util.Base64.getUrlDecoder().decode((String) jwk.get("x")).length);
        assertEquals(32, java.util.Base64.getUrlDecoder().decode((String) jwk.get("y")).length);
    }
}
