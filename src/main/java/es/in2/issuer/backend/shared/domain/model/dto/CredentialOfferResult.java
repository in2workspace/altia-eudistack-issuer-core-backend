package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

/**
 * Outcome of delivering one credential offer.
 *
 * <p>{@code emailError} is a report, not a failure: the email and the QR/URI are separate delivery
 * modes of the same offer (FR-11), so a bounced email must not withdraw a URI that was built
 * correctly. Callers decide what a non-null value means for them — an issuance records it per mode
 * and carries on, the refresh endpoint (whose only purpose is the email) turns it into an error.
 * {@code null} means the email was sent, or was never requested.
 */
@Builder
public record CredentialOfferResult(
        String credentialOfferUri,
        String emailError
) {
}
