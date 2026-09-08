package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import es.in2.issuer.backend.shared.domain.util.DidKeyDerivation;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public record HolderKey(Map<String, Object> cnf) {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Nimbus-parseable JWKs, allowlisted to exactly the key type and curve this issuer can actually
    // verify and bind: ES256 is the only algorithm conv-quality-security-gates.md §4.2/§6.1
    // approves, and DidKeyDerivation only knows how to turn a P-256 point into a did:key. Widening
    // this (EUD-168 code-review, F2a) accepted curves/key types the rest of the pipeline could not
    // back up -- an OKP or RSA jwk would pass validation here and then silently fail did:key
    // derivation downstream, which is worse than rejecting it here. A symmetric or private key here
    // is not a binding, it's a leaked secret (EUD-168 F1, conv-quality-security-gates.md §2.2).
    private static final KeyType ALLOWED_KEY_TYPE = KeyType.EC;
    private static final Curve ALLOWED_EC_CURVE = Curve.P_256;
    // Real-world EC P-256 public JWKs are well under 1 KB; this only guards against an attacker
    // handing the parser a pathologically large node before any of the checks above run.
    private static final int MAX_JWK_NODE_BYTES = 8192;

    public HolderKey {
        Objects.requireNonNull(cnf, "cnf");
    }

    /**
     * Parses a {@code holder_key} JSON node into a {@link HolderKey}. Requires the {@code jwk}
     * member -- {@code kid}/{@code x5c} are RFC 7800 confirmation forms this issuer never actually
     * accepts here: they carry no key material this path can verify without a wallet, and the
     * OID4VCI key-proof path (the other place a {@code cnf} form matters) builds its own
     * {@code BindingInfo} directly in {@code Oid4VciCredentialWorkflowImpl} and never calls this
     * class. An earlier version of this parser accepted all three RFC 7800 forms on the theory that
     * the other two were needed elsewhere; code-review (F1a, D3) found they were not, and dead,
     * unvalidated code that even looks needed is worse than no code -- it is exactly what would have
     * let a future caller reintroduce F1a by accident.
     */
    public static HolderKey fromJson(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            throw new InvalidHolderKeyException(
                    "holder_key is required for this credential type, in every delivery mode: its schema "
                            + "declares no proof_types_supported, so no wallet key proof will ever "
                            + "arrive and the request is the only source of a holder key");
        }
        JsonNode jwkNode = node.isObject() ? node.get("jwk") : null;
        if (jwkNode == null || jwkNode.isNull()) {
            throw new InvalidHolderKeyException("invalid holder_key: expected a jwk member");
        }
        return new HolderKey(Map.of("jwk", validateAndCanonicalizeJwk(jwkNode)));
    }

    /**
     * Parses the candidate {@code jwk} with Nimbus and rejects anything that is not an EC P-256
     * public key: private key material, symmetric ({@code oct}) keys, any other key type or curve.
     * This is the sole point where a caller-supplied {@code holder_key} becomes the {@code cnf} of a
     * signed credential (AD-8), so it is the sole point that has to hold the line (S1).
     *
     * <p>Builds the returned map explicitly from the parsed key's own coordinates -- {@code kty},
     * {@code crv}, {@code x}, {@code y}, and nothing else -- rather than trusting
     * {@link JWK#toJSONObject()} (code-review D2): Nimbus's own serialization preserves every
     * <em>recognized</em> JWK member the caller sent alongside the coordinates ({@code x5u},
     * {@code kid}, {@code alg}, {@code use}...), not just the four this issuer ever asked for. An
     * unvalidated {@code x5u} is an attacker-chosen URL a verifier might dereference to resolve the
     * confirmation key -- signed into the credential by this issuer.
     *
     * <p>Re-encoding the coordinates at a fixed field-size length also closes D1: Nimbus validates
     * that {@code x}/{@code y} decode to a point mathematically on the curve, but not that they are
     * encoded at the curve's canonical fixed octet length (RFC 7518 §6.2.1.2) -- a valid point
     * encoded with e.g. one extra leading zero byte passes Nimbus's check, then breaks
     * {@link DidKeyDerivation}'s fixed-32-byte array arithmetic. That exception was silently
     * swallowed into a random fallback identifier, which the delivery workflows correctly refuse to
     * bind -- but refusing to bind left whatever {@code mandatee.id} the caller supplied completely
     * unchallenged, the exact cnf&harr;mandatee.id mismatch this whole mechanism exists to prevent.
     * Re-encoding here means every {@code jwk} this method returns decodes to exactly 32 bytes.
     */
    private static Map<String, Object> validateAndCanonicalizeJwk(JsonNode value) {
        if (!value.isObject() || value.isEmpty()) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk must be a non-empty JSON object");
        }
        String json;
        try {
            json = OBJECT_MAPPER.writeValueAsString(value);
        } catch (Exception _) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk could not be read");
        }
        if (json.getBytes(StandardCharsets.UTF_8).length > MAX_JWK_NODE_BYTES) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk exceeds the maximum allowed size");
        }

        JWK jwk;
        try {
            jwk = JWK.parse(json);
        } catch (ParseException _) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk is not a well-formed JWK");
        }

        if (jwk.isPrivate()) {
            throw new InvalidHolderKeyException("invalid holder_key: jwk must not contain private key material");
        }
        if (!ALLOWED_KEY_TYPE.equals(jwk.getKeyType()) || !(jwk instanceof ECKey ecKey)
                || !ALLOWED_EC_CURVE.equals(ecKey.getCurve())) {
            throw new InvalidHolderKeyException(
                    "invalid holder_key: unsupported jwk key type or curve, only EC '" + ALLOWED_EC_CURVE + "' is accepted");
        }

        int fieldSizeBits = ALLOWED_EC_CURVE.toECParameterSpec().getCurve().getField().getFieldSize();
        Map<String, Object> canonical = new LinkedHashMap<>();
        canonical.put("kty", ALLOWED_KEY_TYPE.getValue());
        canonical.put("crv", ALLOWED_EC_CURVE.getName());
        canonical.put("x", ECKey.encodeCoordinate(fieldSizeBits, ecKey.getX().decodeToBigInteger()).toString());
        canonical.put("y", ECKey.encodeCoordinate(fieldSizeBits, ecKey.getY().decodeToBigInteger()).toString());
        return canonical;
    }
}
