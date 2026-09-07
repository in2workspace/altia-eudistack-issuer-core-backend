package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

/**
 * RFC 9457 Problem Details, scoped to one failed {@link ChannelResponse} (EUD-167 D-5/D-6). A
 * dedicated record rather than reusing {@code GlobalErrorMessage}: that type lives in
 * {@code shared.infrastructure.controller.error}, and this one is a domain-layer DTO -- importing it
 * here would pull an infrastructure type into the domain model.
 */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ChannelError(
        @JsonProperty("type") String type,
        @JsonProperty("title") String title,
        @JsonProperty("status") int status,
        @JsonProperty("detail") String detail
) {
}
