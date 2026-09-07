package es.in2.issuer.backend.shared.domain.model.dto.credential;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.domain.model.HolderKey;

import java.util.Map;

/**
 * Codec for the {@code cnf} claim as persisted on the {@code issuance} row (EUD-168 AD-8).
 *
 * <p>The credential types exempt from ADR-110 declare no {@code proof_types_supported}, so their
 * holder key arrives once — in the issuance request — and is needed again in a later request, at the
 * OID4VCI Credential Endpoint, where no key proof will arrive to replace it. The signing path speaks
 * in {@code Map<String, Object>}; the row stores text. This translates between the two, in one place,
 * so neither workflow needs an {@link ObjectMapper} of its own for a single field.
 */
public final class HolderCnfJson {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private HolderCnfJson() {
    }

    /** {@code null} for an absent or empty cnf, so the column stays unset for non-exempt types. */
    public static String write(Map<String, Object> cnf) {
        if (cnf == null || cnf.isEmpty()) {
            return null;
        }
        try {
            return OBJECT_MAPPER.writeValueAsString(cnf);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize holder cnf", e);
        }
    }

    /**
     * Empty map for an absent value, so callers can fall back to the key-proof binding.
     *
     * <p>{@code private} (EUD-168 TD-15): {@link #readValidated} is the only production entry
     * point since TD-13 -- a public, unvalidated sibling sitting next to it is exactly the
     * reintroduction hazard {@link HolderKey}'s own javadoc warns about for the write side.
     */
    private static Map<String, Object> read(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            // Jackson deserializes the JSON literal "null" to a Java null, not an empty map
            // (TD-15) -- callers must not have to null-check on top of the blank check above.
            Map<String, Object> result = OBJECT_MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {});
            return result == null ? Map.of() : result;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize holder cnf", e);
        }
    }

    /**
     * Reads the persisted {@code cnf} and re-validates its shape through {@link HolderKey#fromJson}
     * before returning it (EUD-168 TD-13).
     *
     * <p>The only writer of this column always derives its value from
     * {@code HolderKey.fromJson(...).cnf()}, so a well-formed row is always {@code {"jwk": {kty,
     * crv, x, y}}} -- but reading it back without re-checking that shape would trust it rather
     * than verify it, and the write path is the sole point that ever held the line (S1).
     * Re-running the same canonicalization pass here closes that gap: a row a client could never
     * have produced through the normal write path (this column is write-once at insert) cannot
     * silently reach a signed credential's {@code cnf} claim just because it deserializes as valid
     * JSON.
     *
     * <p>Empty for an absent (null or blank) value -- that is the legitimate "no cnf yet" case for
     * a type that reached this column without ever populating it, and must fall through to the
     * key-proof binding rather than fail closed. A present-but-empty value ({@code "{}"}) is NOT
     * treated as absent (EUD-168 TD-15): it deserializes as an object with no {@code jwk} member,
     * so {@link HolderKey#fromJson} rejects it the same as any other malformed shape.
     *
     * @throws es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException if the
     *         persisted value is present but not a well-formed EC P-256 public {@code jwk}
     */
    public static Map<String, Object> readValidated(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        JsonNode node = OBJECT_MAPPER.valueToTree(read(json));
        return HolderKey.fromJson(node).cnf();
    }
}
