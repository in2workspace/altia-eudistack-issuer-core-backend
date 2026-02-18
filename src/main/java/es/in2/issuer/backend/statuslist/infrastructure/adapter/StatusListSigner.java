package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningContext;
import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListCredentialSerializationException;
import es.in2.issuer.backend.statuslist.domain.spi.CredentialPayloadSigner;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;

import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@RequiredArgsConstructor
@Component
public class StatusListSigner implements CredentialPayloadSigner {

    private final SigningProvider signingProvider;
    private final ObjectMapper objectMapper;

    public Mono<String> sign(Map<String, Object> payload, String token, Long listId) {
        requireNonNullParam(payload, "payload");
        requireNonNullParam(token, "token");

        return toJson(payload)
                .flatMap(json -> {
                    SigningRequest req = new SigningRequest(
                            SigningType.JADES,
                            json,
                            new SigningContext(token, null, null)
                    );

                    return signingProvider.sign(req)
                            .map(SigningResult::data)
                            .flatMap(jwt -> {
                                if (jwt == null || jwt.trim().isEmpty()) {
                                    return Mono.error(new SigningException("StatusList signer returned empty JWT; listId=" + listId));
                                }
                                return Mono.just(jwt);
                            });
                })
                .onErrorMap(ex -> {
                    if (ex instanceof SigningException && ex.getMessage() != null && ex.getMessage().startsWith("StatusList signer returned empty JWT")) {
                        return ex;
                    }
                    return new SigningException("StatusList signing failed; listId=" + listId, ex);
                });
    }

    private Mono<String> toJson(Map<String, Object> payload) {
        return Mono.fromCallable(() -> objectMapper.writeValueAsString(payload))
                .onErrorMap(JsonProcessingException.class, StatusListCredentialSerializationException::new);
    }
}
