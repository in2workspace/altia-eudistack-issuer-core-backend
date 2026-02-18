package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.*;
import java.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import es.in2.issuer.backend.shared.domain.util.JwtUtils;
import es.in2.issuer.backend.signing.domain.exception.SignatureProcessingException;
import es.in2.issuer.backend.signing.domain.exception.SignedDataParsingException;
import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import es.in2.issuer.backend.signing.infrastructure.config.RemoteSignatureConfig;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class RemoteSignatureServiceImpl implements RemoteSignatureService {

    private final ObjectMapper objectMapper;
    private final QtspAuthClient qtspAuthClient;
    private final HttpUtils httpUtils;
    private final JwtUtils jwtUtils;
    private final RemoteSignatureConfig remoteSignatureConfig;
    private static final String SAD_NAME = "SAD";
    private static final String SERIALIZING_ERROR = "Error serializing request body to JSON";
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;

    /**
     * Signs an ISSUED credential (user-related credential).
     *
     * <p>
     * Issued credentials represent user-facing identities such as:
     * <ul>
     *   <li>Employee credentials</li>
     *   <li>Machine credentials</li>
     *   <li>Label / badge credentials</li>
     * </ul>
     *
     * <p>
     * These credentials have a special signing lifecycle:
     * <ul>
     *   <li>The signature may be <b>deferred</b> if the remote signing fails</li>
     *   <li>After retries are exhausted, the flow switches to <b>ASYNC mode</b></li>
     *   <li>An additional <b>post-processing step</b> is triggered (e.g. email notification)</li>
     * </ul>
     *
     * <p>
     * Deferred metadata is removed only after a successful signature.
     *
     */
    @Override
    //TODO Cuando se implementen los "settings" del issuer, se debe pasar el clientId, secret, etc. como parámetros en lugar de var entorno
    public Mono<SignedData> signIssuedCredential(
            SignatureRequest signatureRequest,
            String token,
            String procedureId,
            String email
    ) {
        log.debug(
                "RemoteSignatureServiceImpl - signIssuedCredential, signatureRequest: {}, token: {}, procedureId: {}, email: {}",
                signatureRequest, token, procedureId, email
        );

        return signWithRetry(signatureRequest, token, "signIssuedCredential")
                .doOnSuccess(result -> {
                    log.info("Successfully Signed");
                    log.info("Procedure with id: {}", procedureId);
                    log.info("at time: {}", new Date());
                    deferredCredentialMetadataService.deleteDeferredCredentialMetadataById(procedureId);
                });
    }

    /**
     * Signs a SYSTEM credential.
     *
     * <p>
     * System credentials are internal, platform-level credentials and
     * <b>do not follow the issued credential lifecycle</b>.
     *
     * <p>
     * Characteristics:
     * <ul>
     *   <li>No deferred signing</li>
     *   <li>No async recovery flow</li>
     *   <li>No post-signature handling (email, procedure tracking, etc.)</li>
     * </ul>
     *
     * <p>
     * Example of system credentials:
     * <ul>
     *   <li>VC StatusListCredential</li>
     * </ul>
     *
     */
    @Override
    public Mono<SignedData> signSystemCredential(
            SignatureRequest signatureRequest,
            String token
    ) {
        log.debug(
                "RemoteSignatureServiceImpl - signSystemCredential, signatureRequest: {}, token: {}",
                signatureRequest, token
        );

        return signWithRetry(signatureRequest, token, "signSystemCredential");
    }

    private Mono<SignedData> signWithRetry(
            SignatureRequest signatureRequest,
            String token,
            String operationName
    ) {
        return Mono.defer(() -> executeSigningFlow(signatureRequest, token))
                .doOnSuccess(signedData -> {
                    int signedLength = (signedData != null && signedData.data() != null)
                            ? signedData.data().length()
                            : 0;

                    log.info(
                            "Remote signing succeeded ({}). resultType={}, signedLength={}",
                            operationName,
                            signedData != null ? signedData.type() : null,
                            signedLength
                    );
                })
                .retryWhen(
                        Retry.backoff(3, Duration.ofSeconds(1))
                                .maxBackoff(Duration.ofSeconds(5))
                                .jitter(0.5)
                                .filter(QtspRetryPolicy::isRecoverable)
                                .doBeforeRetry(retrySignal -> {
                                    long attempt = retrySignal.totalRetries() + 1;
                                    Throwable failure = retrySignal.failure();
                                    String msg = failure != null ? failure.getMessage() : "n/a";

                                    log.warn(
                                            "Retrying remote signing ({}). attempt={} of 3, reason={}",
                                            operationName, attempt, msg
                                    );
                                })
                )
                .doOnError(ex ->
                        log.error(
                                "Remote signing failed after retries ({}). reason={}",
                                operationName, ex.getMessage(), ex
                        )
                );
    }

    private Mono<SignedData> executeSigningFlow(SignatureRequest signatureRequest, String token) {
        return getSignedSignature(signatureRequest, token)
                .flatMap(response -> {
                    try {
                        return Mono.just(toSignedData(response));
                    } catch (SignedDataParsingException ex) {
                        return Mono.error(new RemoteSignatureException("Error parsing signed data", ex));
                    }
                });
    }


    public Mono<String> getSignedSignature(SignatureRequest signatureRequest, String token) {
        return switch (remoteSignatureConfig.getRemoteSignatureType()) {
            case SIGNATURE_REMOTE_TYPE_SERVER -> getSignedDocumentDSS(signatureRequest, token);
            case SIGNATURE_REMOTE_TYPE_CLOUD -> getSignedDocumentExternal(signatureRequest);
            default -> Mono.error(new RemoteSignatureException("Remote signature service not available"));
        };
    }

    private Mono<String> getSignedDocumentDSS(SignatureRequest signatureRequest, String token) {
        String signatureRemoteServerEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/api/v1"
                + remoteSignatureConfig.getRemoteSignatureSignPath();
        String signatureRequestJSON;

        log.info("Requesting signature to DSS service");

        try {
            signatureRequestJSON = objectMapper.writeValueAsString(signatureRequest);
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException(SERIALIZING_ERROR, e));
        }
        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, token));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        return httpUtils.postRequest(signatureRemoteServerEndpoint, headers, signatureRequestJSON)
                .doOnError(error -> log.error("Error signing credential with server method: {}", error.getMessage()));
    }

    public Mono<String> getSignedDocumentExternal(SignatureRequest signatureRequest) {
        log.info("Requesting signature to external service");
        return qtspAuthClient.requestAccessToken(signatureRequest, SIGNATURE_REMOTE_SCOPE_CREDENTIAL)
                .flatMap(accessToken -> requestSad(accessToken)
                        .flatMap(sad -> sendSignatureRequest(signatureRequest, accessToken, sad)
                                .flatMap(responseJson -> processSignatureResponse(signatureRequest, responseJson))));
    }

    public Mono<String> requestSad(String accessToken) {
        String credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        int numSignatures = 1;
        String authDataId = "password";
        String authDataValue = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        String signatureGetSadEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/authorize";

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put(CREDENTIAL_ID, credentialID);
        requestBody.put(NUM_SIGNATURES, numSignatures);
        Map<String, String> authEntry = new HashMap<>();
        authEntry.put(AUTH_DATA_ID, authDataId);
        authEntry.put(AUTH_DATA_VALUE, authDataValue);
        requestBody.put(AUTH_DATA, List.of(authEntry));

        String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(requestBody);
        } catch (JsonProcessingException e) {
            return Mono.error(new SadException("Error serializing JSON request body"));
        }
        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        return httpUtils.postRequest(signatureGetSadEndpoint, headers, jsonBody)
                .flatMap(responseJson -> Mono.fromCallable(() -> {
                    try {
                        Map<String, Object> responseMap = objectMapper.readValue(responseJson, Map.class);
                        if (!responseMap.containsKey(SAD_NAME)) {
                            throw new SadException("SAD missing in response");
                        }
                        return (String) responseMap.get(SAD_NAME);
                    } catch (JsonProcessingException e) {
                        throw new SadException("Error parsing SAD response");
                    }
                }))
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized: Invalid credentials"));
                    }
                    return Mono.error(ex);
                })
                .doOnError(error -> log.error("Error retrieving access token: {}", error.getMessage()));
    }

    private Mono<String> sendSignatureRequest(SignatureRequest signatureRequest, String accessToken, String sad) {
        String credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        String signatureRemoteServerEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/signatures/signDoc";
        String signatureQualifier = "eu_eidas_aesealqc";
        String signatureFormat = "J";
        String conformanceLevel = "Ades-B";
        String signAlgorithm = "OID_sign_algorithm";

        String base64Document = Base64.getEncoder().encodeToString(signatureRequest.data().getBytes(StandardCharsets.UTF_8));
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put(CREDENTIAL_ID, credentialID);
        requestBody.put(SAD_NAME, sad);
        requestBody.put("signatureQualifier", signatureQualifier);
        List<Map<String, String>> documents = List.of(
                Map.of(
                        "document", base64Document,
                        "signature_format", signatureFormat,
                        "conformance_level", conformanceLevel,
                        "signAlgo", signAlgorithm
                )
        );
        requestBody.put("documents", documents);

        String requestBodySignature;
        try {
            requestBodySignature = objectMapper.writeValueAsString(requestBody);
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException(SERIALIZING_ERROR, e));
        }
        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        return httpUtils.postRequest(signatureRemoteServerEndpoint, headers, requestBodySignature)
                .doOnError(error -> log.error("Error sending credential to sign: {}", error.getMessage()));
    }

    public Mono<String> processSignatureResponse(SignatureRequest signatureRequest, String responseJson) {
        return Mono.fromCallable(() -> {
            try {
                Map<String, List<String>> responseMap = objectMapper.readValue(responseJson, Map.class);
                List<String> documentsWithSignatureList = responseMap.get("DocumentWithSignature");

                if (documentsWithSignatureList == null || documentsWithSignatureList.isEmpty()) {
                    throw new SignatureProcessingException("No signature found in the response");
                }
                String documentsWithSignature = documentsWithSignatureList.get(0);
                String documentsWithSignatureDecoded = new String(Base64.getDecoder().decode(documentsWithSignature), StandardCharsets.UTF_8);
                String receivedPayloadDecoded = jwtUtils.decodePayload(documentsWithSignatureDecoded);
                if (jwtUtils.areJsonsEqual(receivedPayloadDecoded, signatureRequest.data())) {
                    return objectMapper.writeValueAsString(Map.of(
                            "type", signatureRequest.configuration().type().name(),
                            "data", documentsWithSignatureDecoded
                    ));
                } else {
                    throw new SignatureProcessingException("Signed payload received does not match the original data");
                }
            } catch (JsonProcessingException e) {
                throw new SignatureProcessingException("Error parsing signature response", e);
            }
        });
    }


    private SignedData toSignedData(String signedSignatureResponse) throws SignedDataParsingException {
        try {
            return objectMapper.readValue(signedSignatureResponse, SignedData.class);
        } catch (IOException e) {
            log.error("Error: {}", e.getMessage());
            throw new SignedDataParsingException("Error parsing signed data");
        }
    }

}