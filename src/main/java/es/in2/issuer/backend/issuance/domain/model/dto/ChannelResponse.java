package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

/**
 * One item of {@code responses[]} (EUD-167 D-5/D-6): the channel that was requested, its internal
 * HTTP-like status, and either {@code body} (success) or {@code error} (failure, RFC 9457) -- never
 * both, {@code @JsonInclude(NON_NULL)} drops whichever one is unset.
 */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ChannelResponse(
        @JsonProperty("channel") String channel,
        @JsonProperty("status") int status,
        @JsonProperty("body") ChannelBody body,
        @JsonProperty("error") ChannelError error
) {
}
