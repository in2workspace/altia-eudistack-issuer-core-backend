package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import es.in2.issuer.backend.signing.infrastructure.qtsp.signhash.QtspSignHashClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwsSignHashServiceImpl implements JwsSignHashService {

    public static final String HASH_ALGO_OID_SHA256 = "2.16.840.1.101.3.4.2.1";
    public static final String SIGN_ALGO_OID_ES256 = "1.2.840.10045.4.3.2";

    private final HashGeneratorService hashGeneratorService;
    private final QtspSignHashClient qtspSignHashClient;

    @Override
    public Mono<String> signJwtWithSignHash(String accessToken, String headerJson, String payloadJson) {

        final String headerB64Url;
        final String payloadB64Url;

        try {
            headerB64Url = Base64UrlUtils.encodeUtf8(headerJson);
            payloadB64Url = Base64UrlUtils.encodeUtf8(payloadJson);
        } catch (Exception e) {
            return Mono.error(new RemoteSignatureException("Failed to build JWS header/payload", e));
        }

        String signingInput = headerB64Url + "." + payloadB64Url;
        byte[] signingInputBytes = signingInput.getBytes(StandardCharsets.US_ASCII);

        final String hashB64Url;
        try {
            byte[] digest = hashGeneratorService.sha256Digest(signingInputBytes);
            hashB64Url = Base64UrlUtils.encode(digest);
        } catch (Exception e) {
            return Mono.error(new RemoteSignatureException("Failed to compute signingInput digest", e));
        }

        return qtspSignHashClient
                .authorizeForHash(accessToken, hashB64Url, HASH_ALGO_OID_SHA256)
                .retryWhen(signHashRetrySpec("csc.authorizeForHash"))
                .flatMap(sad ->
                        qtspSignHashClient
                                .signHash(
                                        accessToken,
                                        sad,
                                        hashB64Url,
                                        HASH_ALGO_OID_SHA256,
                                        SIGN_ALGO_OID_ES256
                                )
                                .retryWhen(signHashRetrySpec("csc.signHash"))
                )
                .map(signatureB64Url -> signingInput + "." + signatureB64Url)
                .doOnSuccess(jwt ->
                        log.info("signHash completed successfully. JWS length={}", jwt.length())
                )
                .doOnError(ex ->
                        log.error("signHash failed after retries. reason={}", ex.getMessage(), ex)
                );
    }

    private Retry signHashRetrySpec(String operationName) {
        return Retry.backoff(3, Duration.ofSeconds(1))
                .maxBackoff(Duration.ofSeconds(5))
                .jitter(0.5)
                .filter(QtspRetryPolicy::isRecoverable)
                .doBeforeRetry(rs -> {
                    long attempt = rs.totalRetries() + 1;
                    Throwable failure = rs.failure();
                    String msg = failure != null ? failure.getMessage() : "n/a";

                    log.warn(
                            "Retrying {}. attempt={} of 3, reason={}",
                            operationName,
                            attempt,
                            msg
                    );
                });
    }
}