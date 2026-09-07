package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

/**
 * The success payload of one {@link ChannelResponse} (EUD-167 D-6): {@code signed_credential} for the
 * {@code direct} channel, {@code credential_offer_uri} for {@code ui}/{@code email} -- whichever
 * applies is the only one Jackson serializes.
 */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ChannelBody(
        @JsonProperty("signed_credential") String signedCredential,
        @JsonProperty("credential_offer_uri") String credentialOfferUri
) {
}
