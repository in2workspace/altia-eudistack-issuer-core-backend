package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.signing.domain.model.SigningContext;
import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import org.mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.SadException;
import es.in2.issuer.backend.signing.domain.exception.SignatureProcessingException;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import es.in2.issuer.backend.shared.domain.util.JwtUtils;
import es.in2.issuer.backend.signing.infrastructure.config.RemoteSignatureConfig;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;


@ExtendWith(MockitoExtension.class)
class RemoteSignatureServiceImplTest {

    @Mock private ObjectMapper objectMapper;
    @Mock private QtspAuthClient qtspAuthClient;
    @Mock private HttpUtils httpUtils;
    @Mock private JwtUtils jwtUtils;
    @Mock private RemoteSignatureConfig remoteSignatureConfig;
    @Mock private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @InjectMocks
    private RemoteSignatureServiceImpl remoteSignatureService;

    @Test
    void signIssuedCredential_serverMode_success() throws Exception {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_SERVER);
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("http://remote-signature-dss.com");
        when(remoteSignatureConfig.getRemoteSignatureSignPath()).thenReturn("/sign");

        SigningContext context = new SigningContext("token", "proc", "email");

        SigningRequest req = new SigningRequest(
                SigningType.COSE,
                "data",
                context
        );

        String endpoint = "http://remote-signature-dss.com/api/v1/sign";
        String reqJson = "{\"req\":true}";
        String respJson = "{\"type\":\"COSE\",\"data\":\"signed\"}";

        when(objectMapper.writeValueAsString(req)).thenReturn(reqJson);
        when(httpUtils.postRequest(eq(endpoint), anyList(), eq(reqJson))).thenReturn(Mono.just(respJson));

        SigningResult signingResult = new SigningResult(SigningType.COSE, "signed");
        when(objectMapper.readValue(respJson, SigningResult.class)).thenReturn(signingResult);

        StepVerifier.create(remoteSignatureService.signIssuedCredential(req, "token", "proc", "email"))
                .expectNext(signingResult)
                .verifyComplete();

        verify(deferredCredentialMetadataService).deleteDeferredCredentialMetadataById("proc");
    }

    @Test
    void signSystemCredential_cloudMode_success() throws Exception {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_CLOUD);
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://api.external.com");
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("cred-id");
        when(remoteSignatureConfig.getRemoteSignatureCredentialPassword()).thenReturn("pwd");

        SigningContext context = new SigningContext("token", "proc", "email");

        SigningRequest req = new SigningRequest(
                SigningType.COSE,
                "{\"a\":1}",
                context
        );
        
        when(qtspAuthClient.requestAccessToken(req, SIGNATURE_REMOTE_SCOPE_CREDENTIAL))
                .thenReturn(Mono.just("access-token"));

        when(httpUtils.postRequest(eq("https://api.external.com/csc/v2/credentials/authorize"), anyList(), anyString()))
                .thenReturn(Mono.just("{\"SAD\":\"sad-123\"}"));
        when(objectMapper.readValue("{\"SAD\":\"sad-123\"}",Map.class))
                .thenReturn(Map.of("SAD", "sad-123"));

        String jwtOrJades = "signed-jwt";
        String base64Signed = Base64.getEncoder().encodeToString(jwtOrJades.getBytes(StandardCharsets.UTF_8));
        String signDocResponse = "{\"DocumentWithSignature\":[\"" + base64Signed + "\"]}";

        when(httpUtils.postRequest(eq("https://api.external.com/csc/v2/signatures/signDoc"), anyList(), anyString()))
                .thenReturn(Mono.just(signDocResponse));
        when(objectMapper.readValue(signDocResponse, Map.class))
                .thenReturn(Map.of("DocumentWithSignature", List.of(base64Signed)));

        // processSignatureResponse compares payloads
        when(jwtUtils.decodePayload(jwtOrJades)).thenReturn("{\"a\":1}");
        when(jwtUtils.areJsonsEqual("{\"a\":1}", req.data())).thenReturn(true);

        // final JSON that executeSigningFlow parses to SigningResult
        String signedDataJson = "{\"type\":\"JADES\",\"data\":\"" + jwtOrJades + "\"}";
        when(objectMapper.writeValueAsString(any(Map.class))).thenReturn(signedDataJson);
        SigningResult expected = new SigningResult(SigningType.JADES, jwtOrJades);
        when(objectMapper.readValue(signedDataJson, SigningResult.class)).thenReturn(expected);

        StepVerifier.create(remoteSignatureService.signSystemCredential(req, "ignored-token-here"))
                .expectNext(expected)
                .verifyComplete();

        verify(deferredCredentialMetadataService, never()).deleteDeferredCredentialMetadataById(anyString());
    }

    @Test
    void getSignedDocumentExternal_sadMissing_shouldFailWithSadException() throws Exception {
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://api.external.com");
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("cred-id");
        when(remoteSignatureConfig.getRemoteSignatureCredentialPassword()).thenReturn("pwd");

        SigningContext context = new SigningContext("token", "proc", "email");

        SigningRequest req = new SigningRequest(
                SigningType.COSE,
                "{\"a\":1}",
                context
        );

        when(qtspAuthClient.requestAccessToken(req,SIGNATURE_REMOTE_SCOPE_CREDENTIAL))
                .thenReturn(Mono.just("access-token"));

        when(httpUtils.postRequest(
                eq("https://api.external.com/csc/v2/credentials/authorize"),
                anyList(),
                isNull()
        )).thenReturn(Mono.just("{\"NO_SAD\":\"x\"}"));

        when(objectMapper.readValue("{\"NO_SAD\":\"x\"}", Map.class))
                .thenReturn(Map.of("NO_SAD", "x"));

        StepVerifier.create(remoteSignatureService.getSignedDocumentExternal(req))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(SadException.class);
                    assertThat(ex.getMessage()).contains("SAD");
                })
                .verify();
    }

    @Test
    void processSignatureResponse_shouldFail_whenNoSignature() throws Exception {
        SigningContext context = new SigningContext("token", "proc", "email");

        SigningRequest req = new SigningRequest(
                SigningType.COSE,
                "{\"a\":1}",
                context
        );

        String responseJson = "{\"DocumentWithSignature\":[]}";
        when(objectMapper.readValue(responseJson,Map.class))
                .thenReturn(Map.of("DocumentWithSignature", List.of()));

        StepVerifier.create(remoteSignatureService.processSignatureResponse(req, responseJson))
                .expectError(SignatureProcessingException.class)
                .verify();
    }

    @Test
    void processSignatureResponse_shouldFail_whenPayloadMismatch() throws Exception {
        SigningContext context = new SigningContext("token", "proc", "email");

        SigningRequest req = new SigningRequest(
                SigningType.COSE,
                "{\"a\":1}",
                context
        );

        String signedJwt = "signed-jwt";
        String base64Signed = Base64.getEncoder().encodeToString(signedJwt.getBytes(StandardCharsets.UTF_8));
        String responseJson = "{\"DocumentWithSignature\":[\"" + base64Signed + "\"]}";

        when(objectMapper.readValue(responseJson, Map.class))
                .thenReturn(Map.of("DocumentWithSignature", List.of(base64Signed)));

        // decodePayload returns something different
        when(jwtUtils.decodePayload(signedJwt)).thenReturn("{\"a\":999}");
        when(jwtUtils.areJsonsEqual("{\"a\":999}", req.data())).thenReturn(false);

        StepVerifier.create(remoteSignatureService.processSignatureResponse(req, responseJson))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(SignatureProcessingException.class);
                    assertThat(ex.getMessage()).contains("does not match");
                })
                .verify();
    }

    @Test
    void signIssuedCredential_cloudMode_retries_thenSucceeds() throws Exception {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_CLOUD);
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://api.external.com");
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("cred-id");
        when(remoteSignatureConfig.getRemoteSignatureCredentialPassword()).thenReturn("pwd");
        SigningContext context = new SigningContext("token", "proc", "email");

        SigningRequest req = new SigningRequest(
                SigningType.COSE,
                "{\"a\":1}",
                context
        );

        when(qtspAuthClient.requestAccessToken(req, SIGNATURE_REMOTE_SCOPE_CREDENTIAL))
                .thenReturn(Mono.just("access-token"));

        when(httpUtils.postRequest(eq("https://api.external.com/csc/v2/credentials/authorize"), anyList(), anyString()))
                .thenReturn(Mono.just("{\"SAD\":\"sad-123\"}"));
        when(objectMapper.readValue("{\"SAD\":\"sad-123\"}",Map.class))
                .thenReturn(Map.of("SAD", "sad-123"));

        WebClientResponseException serverError = WebClientResponseException.create(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                HttpHeaders.EMPTY,
                null,
                null
        );

        String jwtOrJades = "signed-jwt";
        String base64Signed = Base64.getEncoder().encodeToString(jwtOrJades.getBytes(StandardCharsets.UTF_8));
        String signDocResponse = "{\"DocumentWithSignature\":[\"" + base64Signed + "\"]}";

        when(httpUtils.postRequest(eq("https://api.external.com/csc/v2/signatures/signDoc"), anyList(), anyString()))
                .thenReturn(Mono.error(serverError), Mono.error(serverError), Mono.just(signDocResponse));

        when(objectMapper.readValue(signDocResponse,Map.class))
                .thenReturn(Map.of("DocumentWithSignature", List.of(base64Signed)));

        when(jwtUtils.decodePayload(jwtOrJades)).thenReturn("{\"a\":1}");
        when(jwtUtils.areJsonsEqual("{\"a\":1}",req.data())).thenReturn(true);

        String signedDataJson = "{\"type\":\"JADES\",\"data\":\"" + jwtOrJades + "\"}";
        when(objectMapper.writeValueAsString(any(Map.class))).thenReturn(signedDataJson);

        SigningResult expected = new SigningResult(SigningType.JADES, jwtOrJades);
        when(objectMapper.readValue(signedDataJson, SigningResult.class)).thenReturn(expected);

        StepVerifier.create(remoteSignatureService.signIssuedCredential(req, "token", "proc-1", "mail"))
                .expectNext(expected)
                .verifyComplete();

        verify(httpUtils, times(3)).postRequest(eq("https://api.external.com/csc/v2/signatures/signDoc"), anyList(), anyString());
        verify(deferredCredentialMetadataService).deleteDeferredCredentialMetadataById("proc-1");
    }
}
