package es.in2.issuer.backend.shared.domain.model.enums;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Delivery modes for credentials.
 *
 * <p><b>Ubiquitous language mapping (AD-3, EUD-33):</b>
 *
 * <ul>
 *   <li><b>direct</b> → {@link #DIRECT} ({@code "direct"})</li>
 *   <li><b>wallet</b> → {@link #EMAIL} ({@code "email"}) or {@link #UI} ({@code "ui"}, QR/OID4VCI channel)</li>
 *   <li><b>hybrid</b> → a set of ≥2 modes, e.g. {@code "direct,email"} — it is not an enum value</li>
 * </ul>
 *
 * <p>The HTTP request uses CSV in {@code delivery} (e.g. {@code "direct,email"}).
 * Duplicates are normalized into a {@link Set} without repetition (EC-02).
 */
public enum DeliveryMode {

    EMAIL("email",   true,  false),
    UI   ("ui",      true,  true),
    DIRECT("direct", false, false);

    public final String value;
    public final boolean isOid4vci;
    public final boolean returnsUri;

    DeliveryMode(String value, boolean isOid4vci, boolean returnsUri) {
        this.value = value;
        this.isOid4vci = isOid4vci;
        this.returnsUri = returnsUri;
    }

    /** {@code true} if this mode corresponds to a direct delivery (synchronous direct delivery in the ubiquitous language: "direct"). */
    public boolean isDirect() {
        return !isOid4vci;
    }

    public static Set<DeliveryMode> parse(String delivery) {
        if (delivery == null || delivery.isBlank()) {
            throw new IllegalArgumentException("Delivery mode must not be null or blank");
        }

        Set<DeliveryMode> modes = Arrays.stream(delivery.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> fromValue(s)
                        .orElseThrow(() -> new IllegalArgumentException("Unknown delivery mode: " + s)))
                .collect(Collectors.toSet());

        if (modes.isEmpty()) {
            throw new IllegalArgumentException("At least one delivery mode is required");
        }

        return modes;
    }

    /** Resolves a raw wire value (e.g. {@code "ui"}) back to its {@link DeliveryMode}, if any matches. */
    public static Optional<DeliveryMode> fromValue(String value) {
        return Arrays.stream(values())
                .filter(m -> m.value.equals(value))
                .findFirst();
    }

    public static String toCanonicalCsv(Set<DeliveryMode> modes) {
        if (modes == null || modes.isEmpty()) {
            throw new IllegalArgumentException("At least one delivery mode is required");
        }
        return modes.stream()
                .map(m -> m.value)
                .sorted()
                .collect(Collectors.joining(","));
    }
}
