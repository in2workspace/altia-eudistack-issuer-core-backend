package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class InMemorySigningProvider implements SigningProvider {

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {

            SigningRequestValidator.validate(request);

            return switch (request.type()) {
                case JADES -> Mono.just(new SigningResult(SigningType.JADES, fakeJws(request.data())));
                case COSE -> Mono.just(new SigningResult(SigningType.COSE, fakeCoseBase64(request.data())));
            };
        });
    }

    /**
     * Produces a JWS-like string:
     *   base64url(header).base64url(payload).
     *
     * Header uses alg=none so it's obvious it's non-crypto.
     * This is intended for local/dev/testing only.
     */
    private String fakeJws(String payloadJson) {
        String headerJson = "{\"alg\":\"none\",\"typ\":\"JWT\"}";

        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));

        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

        return header + "." + payload + ".";
    }

    /**
     * For COSE, the workflow expects SigningResult.data() to be Base64 of bytes.
     *
     * The input in your workflow is the CBOR encoded as Base64 (string).
     * We decode it to bytes and re-encode as Base64 (normalized).
     * This yields a valid Base64 payload that downstream can decode+compress+base45.
     */
    private String fakeCoseBase64(String cborBase64Input) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(cborBase64Input);
        } catch (IllegalArgumentException ex) {
            log.warn("COSE input was not valid Base64; using raw UTF-8 bytes as dummy COSE. reason={}", ex.getMessage());
            bytes = cborBase64Input.getBytes(StandardCharsets.UTF_8);
        }
        return Base64.getEncoder().encodeToString(bytes);
    }
}
