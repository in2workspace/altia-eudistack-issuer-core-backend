package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
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

        return toSignatureRequest(payload, token)
                .flatMap(signingProvider::sign)
                .onErrorMap(ex -> new RemoteSignatureException("StatusList signing failed; list ID: " + listId, ex))
                .map(signingResult -> extractJwt(signingResult, listId));
    }

    private Mono<SigningRequest> toSignatureRequest(Map<String, Object> payload, String token) {
        return Mono.fromCallable(() -> {
            String json = objectMapper.writeValueAsString(payload);

            SigningContext context = SigningContext.builder()
                    .token(token)
                    .procedureId(null)
                    .email(null)
                    .build();

            return SigningRequest.builder()
                    .type(SigningType.JADES)
                    .data(json)
                    .context(context)
                    .build();
        }).onErrorMap(JsonProcessingException.class, StatusListCredentialSerializationException::new);
    }

    private String extractJwt(SigningResult signingResult, Long listId) {
        System.out.println("Signing result: " + signingResult);
        if (signingResult == null || signingResult.data() == null || signingResult.data().isBlank()) {
            throw new RemoteSignatureException("Signer returned empty signingResult; list ID: " + listId);
        }
        return signingResult.data();
    }

}
