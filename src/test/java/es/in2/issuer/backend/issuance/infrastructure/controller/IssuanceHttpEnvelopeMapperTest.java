package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceHttpResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IssuanceHttpEnvelopeMapperTest {

    private final IssuanceHttpEnvelopeMapper mapper = new IssuanceHttpEnvelopeMapper();

    @Test
    void toHttpResponse_DirectSucceeded_BodyCarriesSignedCredential() {
        IssuanceResponse response = IssuanceResponse.builder()
                .signedCredential("signed-jwt")
                .deliveryResults(List.of(DeliveryResult.delivered("direct")))
                .build();

        ChannelResponse channel = mapper.toHttpResponse(response).responses().get(0);

        assertThat(channel.channel()).isEqualTo("direct");
        assertThat(channel.status()).isEqualTo(200);
        assertThat(channel.body().signedCredential()).isEqualTo("signed-jwt");
        assertThat(channel.body().credentialOfferUri()).isNull();
        assertThat(channel.error()).isNull();
    }

    @Test
    void toHttpResponse_UiSucceeded_BodyCarriesCredentialOfferUri() {
        IssuanceResponse response = IssuanceResponse.builder()
                .credentialOfferUri("openid-credential-offer://x")
                .deliveryResults(List.of(DeliveryResult.dispatched("ui")))
                .build();

        ChannelResponse channel = mapper.toHttpResponse(response).responses().get(0);

        assertThat(channel.channel()).isEqualTo("ui");
        assertThat(channel.status()).isEqualTo(200);
        assertThat(channel.body().credentialOfferUri()).isEqualTo("openid-credential-offer://x");
        assertThat(channel.body().signedCredential()).isNull();
    }

    /**
     * B1 (code-review, 2026-09-04): an email-only dispatch never gets a URI --
     * {@code CredentialOfferServiceImpl} only builds one when the requested modes include one that
     * {@code returnsUri} (ui does, email alone does not) -- so {@code credentialOfferUri} is null on
     * the domain response. The channel must report a genuine absence (no {@code body} at all), not an
     * uninformative empty object.
     */
    @Test
    void toHttpResponse_EmailOnlySucceeded_HasNoBody() {
        IssuanceResponse response = IssuanceResponse.builder()
                .credentialOfferUri(null)
                .deliveryResults(List.of(DeliveryResult.dispatched("email")))
                .build();

        ChannelResponse channel = mapper.toHttpResponse(response).responses().get(0);

        assertThat(channel.channel()).isEqualTo("email");
        assertThat(channel.status()).isEqualTo(200);
        assertThat(channel.body()).isNull();
        assertThat(channel.error()).isNull();
    }

    /**
     * The combined case: email dispatched alongside ui never carries the URI in its own item -- it was
     * already delivered inside the email itself, not returned to the API caller through this channel.
     * Only ui reports it.
     */
    @Test
    void toHttpResponse_EmailSucceededAlongsideUi_EmailHasNoBodyAndUiCarriesTheCredentialOfferUri() {
        IssuanceResponse response = IssuanceResponse.builder()
                .credentialOfferUri("openid-credential-offer://x")
                .deliveryResults(List.of(
                        DeliveryResult.dispatched("email"),
                        DeliveryResult.dispatched("ui")))
                .build();

        IssuanceHttpResponse httpResponse = mapper.toHttpResponse(response);

        assertThat(httpResponse.responses().get(0).body()).isNull();
        assertThat(httpResponse.responses().get(1).body().credentialOfferUri()).isEqualTo("openid-credential-offer://x");
    }

    @Test
    void toHttpResponse_ChannelFailed_MapsToGeneric503() {
        IssuanceResponse response = IssuanceResponse.builder()
                .deliveryResults(List.of(DeliveryResult.failed("direct", DeliveryErrorCode.SIGNING_FAILED.value())))
                .build();

        ChannelResponse channel = mapper.toHttpResponse(response).responses().get(0);

        assertThat(channel.status()).isEqualTo(503);
        assertThat(channel.body()).isNull();
        assertThat(channel.error().type()).isEqualTo("signing_failed");
        assertThat(channel.error().title()).isEqualTo("Signing failed");
        assertThat(channel.error().status()).isEqualTo(503);
    }

    @Test
    void toHttpResponse_WalletDeliveryTimedOut_MapsTo504() {
        IssuanceResponse response = IssuanceResponse.builder()
                .deliveryResults(List.of(DeliveryResult.failed("ui", DeliveryErrorCode.WALLET_DELIVERY_TIMEOUT.value())))
                .build();

        ChannelResponse channel = mapper.toHttpResponse(response).responses().get(0);

        assertThat(channel.status()).isEqualTo(504);
        assertThat(channel.error().type()).isEqualTo("wallet_delivery_timeout");
    }

    /**
     * Documented-unreachable-in-production fallback (code-review W1): every real failure path tags
     * its {@link DeliveryResult#error()} with a {@link DeliveryErrorCode#value()}, so this branch only
     * fires for a string that matches none of them -- proven here directly rather than left untested.
     */
    @Test
    void toHttpResponse_UnclassifiedErrorCode_FallsBackToGenericTitle() {
        IssuanceResponse response = IssuanceResponse.builder()
                .deliveryResults(List.of(DeliveryResult.failed("email", "not_a_known_code")))
                .build();

        ChannelResponse channel = mapper.toHttpResponse(response).responses().get(0);

        assertThat(channel.status()).isEqualTo(503);
        assertThat(channel.error().type()).isEqualTo("not_a_known_code");
        assertThat(channel.error().title()).isEqualTo("Delivery failed");
    }

    @Test
    void toHttpResponse_NoDeliveryResults_ReturnsEmptyResponsesList() {
        IssuanceResponse response = IssuanceResponse.builder().build();

        assertThat(mapper.toHttpResponse(response).responses()).isEmpty();
    }
}
