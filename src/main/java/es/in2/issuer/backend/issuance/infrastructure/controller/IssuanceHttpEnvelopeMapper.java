package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelBody;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelError;
import es.in2.issuer.backend.issuance.domain.model.dto.ChannelResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceHttpResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Projects the domain-shaped {@link IssuanceResponse} (still flat: {@code signedCredential} /
 * {@code credentialOfferUri} / {@code deliveryResults}, produced by {@code IssuanceWorkflowImpl}
 * unchanged) onto the HTTP envelope EUD-167 D-5/D-6 specifies: one {@code responses[]} entry per
 * requested channel, {@code direct} carrying {@code signed_credential} in its {@code body}, {@code ui}
 * carrying {@code credential_offer_uri} in it <em>only when there is one</em> (see {@link #offerBody}),
 * and {@code email} never carrying a body of its own -- the URI was already delivered inside the email,
 * not returned to the API caller through this channel -- or an RFC 9457 {@code error} for a failed
 * channel. {@link IssuanceController} decides the response-line HTTP status (200/207/500) from the same
 * {@code deliveryResults}; this mapper only shapes the body.
 */
@Component
public class IssuanceHttpEnvelopeMapper {

    public IssuanceHttpResponse toHttpResponse(IssuanceResponse response) {
        List<DeliveryResult> results = response.deliveryResults();
        List<ChannelResponse> channels = results == null
                ? List.of()
                : results.stream().map(result -> toChannelResponse(result, response)).toList();
        return new IssuanceHttpResponse(channels);
    }

    private ChannelResponse toChannelResponse(DeliveryResult result, IssuanceResponse response) {
        return result.status() == DeliveryResult.DeliveryOutcome.FAILED
                ? failedChannel(result)
                : succeededChannel(result, response);
    }

    private ChannelResponse succeededChannel(DeliveryResult result, IssuanceResponse response) {
        ChannelBody body = buildChannelBody(result, response);
        return ChannelResponse.builder()
                .channel(result.mode())
                .status(200)
                .body(body)
                .build();
    }

    private ChannelBody buildChannelBody(DeliveryResult result, IssuanceResponse response) {
        // direct signs synchronously in this same request and returns the credential itself; a mode
        // that returnsUri (only ui today) points at the dispatched OID4VCI offer when there is one to
        // point at (there isn't always -- CredentialOfferServiceImpl only builds a URI when the
        // requested modes include one that returnsUri -- an email-only dispatch has nothing to report
        // here, so body stays null rather than an uninformative empty object, B1 code-review). Any
        // other mode (email today) never carries the URI in its own item, even alongside ui: the URI
        // was already delivered inside the email body, not returned to the API caller through this
        // channel of the response.
        //
        // Resolved via DeliveryMode.fromValue + isDirect()/returnsUri (TD-16) rather than comparing
        // result.mode() against string literals: a literal check silently treats any future
        // DeliveryMode as "no URI" even if its returnsUri says otherwise -- the same class of bug B1
        // already was once.
        DeliveryMode mode = DeliveryMode.fromValue(result.mode()).orElse(null);
        if (mode != null && mode.isDirect()) {
            return ChannelBody.builder()
                    .signedCredential(response.signedCredential())
                    .build();
        }

        if (mode != null && mode.returnsUri) {
            return offerBody(response.credentialOfferUri());
        }

        return null;
    }

    private ChannelBody offerBody(String credentialOfferUri) {
        return credentialOfferUri != null
                ? ChannelBody.builder().credentialOfferUri(credentialOfferUri).build()
                : null;
    }

    private ChannelResponse failedChannel(DeliveryResult result) {
        // A stuck dependency times out (504); every other classified stage is a dependency/processing
        // failure the caller cannot retry differently (503). Never the caller's fault -> never 4xx here.
        int status = DeliveryErrorCode.WALLET_DELIVERY_TIMEOUT.value().equals(result.error())
                ? 504
                : 503;
        ChannelError error = ChannelError.builder()
                .type(result.error())
                .title(titleFor(result.error()))
                .status(status)
                .detail("Delivery failed for channel '" + result.mode() + "'")
                .build();
        return ChannelResponse.builder()
                .channel(result.mode())
                .status(status)
                .error(error)
                .build();
    }

    private String titleFor(String code) {
        for (DeliveryErrorCode candidate : DeliveryErrorCode.values()) {
            if (candidate.value().equals(code)) {
                return candidate.title();
            }
        }
        return "Delivery failed";
    }
}
