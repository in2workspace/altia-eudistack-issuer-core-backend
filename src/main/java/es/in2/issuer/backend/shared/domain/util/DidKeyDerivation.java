package es.in2.issuer.backend.shared.domain.util;

import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.UUID;

/**
 * Derives a {@code did:key} identifier from a P-256 EC JWK's public coordinates.
 *
 * <p>Shared between the OID4VCI proof path ({@code buildFromJwk}, EUD-168 AD-9) and the AD-8
 * holder-key path ({@code F2}): both need the same did:key from a JWK's {@code x}/{@code y}, one
 * from a wallet-supplied key proof, the other from the {@code holder_key} of the AD-8 exempt types
 * -- the same shape, the same multicodec (P-256, {@code 0x1200}), the same encoding.
 */
@Slf4j
public final class DidKeyDerivation {

    private DidKeyDerivation() {
    }

    /**
     * @return the {@code did:key} for the given P-256 EC JWK's public coordinates, or a random
     *         {@code urn:uuid} fallback if the coordinates cannot be decoded -- never throws, mirroring
     *         the tolerance the OID4VCI proof path already relied on.
     */
    public static String deriveDidKeyFromJwk(Map<String, Object> jwk) {
        try {
            byte[] xRaw = java.util.Base64.getUrlDecoder().decode((String) jwk.get("x"));
            byte[] yRaw = java.util.Base64.getUrlDecoder().decode((String) jwk.get("y"));

            // Pad to 32 bytes
            byte[] xBytes = new byte[32];
            byte[] yBytes = new byte[32];
            System.arraycopy(xRaw, 0, xBytes, 32 - xRaw.length, xRaw.length);
            System.arraycopy(yRaw, 0, yBytes, 32 - yRaw.length, yRaw.length);

            // Compressed point: 0x02 if y even, 0x03 if y odd
            byte prefix = (yBytes[31] & 0x01) == 0 ? (byte) 0x02 : (byte) 0x03;
            byte[] compressed = new byte[33];
            compressed[0] = prefix;
            System.arraycopy(xBytes, 0, compressed, 1, 32);

            // P-256 multicodec varint prefix: 0x1200 → [0x80, 0x24]
            byte[] keyWithPrefix = new byte[35];
            keyWithPrefix[0] = (byte) 0x80;
            keyWithPrefix[1] = 0x24;
            System.arraycopy(compressed, 0, keyWithPrefix, 2, 33);

            return "did:key:z" + Base58Codec.encode(keyWithPrefix);
        } catch (Exception e) {
            log.warn("Could not derive did:key from JWK, falling back to random subject: {}", e.getMessage());
            return "urn:uuid:" + UUID.randomUUID();
        }
    }
}
