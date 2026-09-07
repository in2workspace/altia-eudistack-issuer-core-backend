package es.in2.issuer.backend.signing.infrastructure.csc.v2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.infrastructure.util.HttpUtils;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.infrastructure.csc.CscApiVersion;
import es.in2.issuer.backend.signing.infrastructure.csc.v2.dto.*;
import es.in2.issuer.backend.signing.infrastructure.csc.v2.mapper.CscV2CertificateInfoMapper;
import es.in2.issuer.backend.signing.infrastructure.csc.auth.CscAuthStrategyResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.AbstractMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class CscV2Adapter implements CscPort {

    private static final String CHAIN = "chain";
    // Digitel's CSC v2 credentials/list returns 500 for a spec-conformant
    // RFC 5646 `lang` string (CSC v2.1.0.1 §8.2 defines `lang` as string;
    // verified against their STG endpoint 2026-09-07). It only accepts the
    // pre-conformance int value. Fikua DSS enforces the spec-correct string.
    // Workaround until Digitel fixes their implementation.
    private static final String DIGITEL_PROVIDER = "digitel";
    private final CscAuthStrategyResolver authResolver;
    private final CscV2CertificateInfoMapper certificateInfoMapper;
    private final ObjectMapper objectMapper;
    private final HttpUtils httpUtils;

    @Override
    public String supportedVersion() {
        return CscApiVersion.V2.getValue();
    }

    @Override
    public Mono<String> requestAccessToken(RemoteSignatureDto cfg, String scope, boolean includeAuthDetails, String credentialData) {
        SigningRequest bridgeRequest = SigningRequest.builder()
                .remoteSignature(cfg)
                .data(credentialData)
                .build();
        return authResolver
                .resolveFromValue(cfg.provider())
                .requestAccessToken(bridgeRequest, scope, includeAuthDetails);
    }

    @Override
    public Mono<CertificateInfo> getCredentialInfo(RemoteSignatureDto cfg, String accessToken, String credentialId) {
        CscV2CredentialsInfoRequest body = new CscV2CredentialsInfoRequest(credentialId, CHAIN, true, true);
        return post(cfg.url() + CscV2Paths.INFO, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> {
                    Map<String, Object> map = objectMapper.readValue(json, new TypeReference<>() {});
                    return certificateInfoMapper.map(map);
                }))
                .onErrorMap(e -> !(e instanceof RemoteSignatureException),
                        e -> new RemoteSignatureException("Failed to fetch credentials/info: " + e.getMessage(), e));
    }

    @Override
    public Mono<Boolean> validateCredentialId(RemoteSignatureDto cfg, String accessToken, String credentialId) {
        CscV2CredentialsListRequest body = new CscV2CredentialsListRequest(true, CHAIN, true, true, true, langFor(cfg), "string");

        String url = cfg.url() + CscV2Paths.LIST;
        return post(url, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> {
                    CscV2CredentialsListResponse resp = objectMapper.readValue(json, CscV2CredentialsListResponse.class);
                    List<String> ids = resp.credentialIds();
                    return ids != null && ids.stream().anyMatch(id -> id.trim().equalsIgnoreCase(credentialId.trim()));
                }))
                .switchIfEmpty(Mono.just(false))
                .onErrorMap(e -> !(e instanceof RemoteSignatureException),
                        e -> new RemoteSignatureException("Failed to list credentials from url: " + url + " " + e.getMessage(), e));
    }

    @Override
    public Mono<List<String>> listCredentialIds(RemoteSignatureDto cfg, String accessToken) {
        CscV2CredentialsListRequest body = new CscV2CredentialsListRequest(true, CHAIN, true, true, true, langFor(cfg), "string");
        return post(cfg.url() + CscV2Paths.LIST, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> {
                    CscV2CredentialsListResponse resp = objectMapper.readValue(json, CscV2CredentialsListResponse.class);
                    return resp.credentialIds() != null ? resp.credentialIds() : List.<String>of();
                }))
                .onErrorMap(e -> !(e instanceof RemoteSignatureException),
                        e -> new RemoteSignatureException("Failed to list credentials: " + e.getMessage(), e));
    }

    @Override
    public Mono<String> authorizeForHash(RemoteSignatureDto cfg, String accessToken, String hashB64Url, String hashAlgoOid) {
        CscV2AuthorizeRequest body = new CscV2AuthorizeRequest(
                cfg.credentialId(),
                1,
                List.of(hashB64Url),
                hashAlgoOid,
                List.of(Map.of("id", "password", "value", cfg.credentialPassword()))
        );
        return post(cfg.url() + CscV2Paths.AUTHORIZE, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> objectMapper.readValue(json, CscV2AuthorizeResponse.class)))
                .flatMap(resp -> {
                    if (resp.sad() == null || resp.sad().isBlank()) {
                        return Mono.error(new RemoteSignatureException("Empty authorize response (missing SAD)"));
                    }
                    return Mono.just(resp.sad());
                })
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized on credentials/authorize (hash)"));
                    }
                    return Mono.error(new RemoteSignatureException("CSC v2 authorize(hash) failed", ex));
                });
    }

    @Override
    public Mono<String> signHash(RemoteSignatureDto cfg, String accessToken, String sad, String hashB64Url, String hashAlgoOid, String signAlgoOid) {
        CscV2SignHashRequest body = new CscV2SignHashRequest(
                cfg.credentialId(),
                sad,
                List.of(hashB64Url),
                hashAlgoOid,
                signAlgoOid
        );
        return post(cfg.url() + CscV2Paths.SIGN_HASH, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> objectMapper.readValue(json, CscV2SignHashResponse.class)))
                .flatMap(resp -> {
                    if (resp.signatures() == null || resp.signatures().isEmpty() || resp.signatures().getFirst() == null) {
                        return Mono.error(new RemoteSignatureException("signHash response missing signatures[0]"));
                    }
                    return Mono.just(resp.signatures().getFirst());
                })
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized on signatures/signHash"));
                    }
                    return Mono.error(new RemoteSignatureException("CSC v2 signHash failed", ex));
                });
    }

    @Override
    public Mono<String> authorizeForDoc(RemoteSignatureDto cfg, String accessToken) {
        CscV2AuthorizeRequest body = new CscV2AuthorizeRequest(
                cfg.credentialId(),
                1,
                null,
                null,
                List.of(Map.of("id", "password", "value", cfg.credentialPassword()))
        );
        return post(cfg.url() + CscV2Paths.AUTHORIZE, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> objectMapper.readValue(json, CscV2AuthorizeResponse.class)))
                .flatMap(resp -> {
                    if (resp.sad() == null || resp.sad().isBlank()) {
                        return Mono.error(new RemoteSignatureException("Empty authorize response (missing SAD)"));
                    }
                    return Mono.just(resp.sad());
                })
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized on credentials/authorize (doc)"));
                    }
                    return Mono.error(new RemoteSignatureException("CSC v2 authorize(doc) failed", ex));
                });
    }

    @Override
    public Mono<String> signDoc(RemoteSignatureDto cfg, String accessToken, String sad, String docB64, String signAlgoOid) {
        CscV2SignDocRequest body = new CscV2SignDocRequest(
                cfg.credentialId(),
                sad,
                "eu_eidas_aesealqc",
                List.of(Map.of(
                        "document", docB64,
                        "signature_format", "J",
                        "conformance_level", "Ades-B-B",
                        "signAlgo", signAlgoOid
                ))
        );
        return post(cfg.url() + CscV2Paths.SIGN_DOC, accessToken, body)
                .flatMap(json -> Mono.fromCallable(() -> {
                    CscV2SignDocResponse resp = objectMapper.readValue(json, CscV2SignDocResponse.class);
                    if (resp.documentWithSignature() == null || resp.documentWithSignature().isEmpty()) {
                        throw new RemoteSignatureException("signDoc response missing DocumentWithSignature");
                    }
                    return resp.documentWithSignature().getFirst();
                }))
                .doOnError(error -> log.error("Error in signDoc: {}", error.getMessage()));
    }

    // Workaround for Digitel's non-conformant credentials/list — see
    // DIGITEL_PROVIDER above.
    private Object langFor(RemoteSignatureDto cfg) {
        return DIGITEL_PROVIDER.equalsIgnoreCase(cfg.provider()) ? 0 : "en-US";
    }

    private Mono<String> post(String url, String accessToken, Object body) {
        String json;
        try {
            json = objectMapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException("Error serializing CSC v2 request body", e));
        }

        List<Map.Entry<String, String>> headers = List.of(
                new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken),
                new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
        );

        return httpUtils.postRequest(url, headers, json);
    }
}
