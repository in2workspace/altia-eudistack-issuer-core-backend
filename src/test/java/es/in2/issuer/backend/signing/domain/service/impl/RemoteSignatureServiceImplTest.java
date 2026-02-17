package es.in2.issuer.backend.signing.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.exception.SadException;
import es.in2.issuer.backend.signing.domain.exception.SignatureProcessingException;
import es.in2.issuer.backend.signing.domain.exception.SignedDataParsingException;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureConfiguration;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import es.in2.issuer.backend.shared.domain.util.JwtUtils;
import es.in2.issuer.backend.signing.infrastructure.config.RemoteSignatureConfig;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

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

        SignatureRequest req = new SignatureRequest(
                new SignatureConfiguration(SignatureType.COSE, Map.of()),
                "data"
        );

        String endpoint = "http://remote-signature-dss.com/api/v1/sign";
        String reqJson = "{\"req\":true}";
        String respJson = "{\"type\":\"COSE\",\"data\":\"signed\"}";

        when(objectMapper.writeValueAsString(req)).thenReturn(reqJson);
        when(httpUtils.postRequest(eq(endpoint), anyList(), eq(reqJson))).thenReturn(Mono.just(respJson));

        SignedData signedData = new SignedData(SignatureType.COSE, "signed");
        when(objectMapper.readValue(respJson, SignedData.class)).thenReturn(signedData);

        StepVerifier.create(remoteSignatureService.signIssuedCredential(req, "token", "proc", "email"))
                .expectNext(signedData)
                .verifyComplete();

        verify(deferredCredentialMetadataService).deleteDeferredCredentialMetadataById("proc");
    }

    @Test
    void signSystemCredential_cloudMode_success() throws Exception {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn(SIGNATURE_REMOTE_TYPE_CLOUD);
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://api.external.com");
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("cred-id");
        when(remoteSignatureConfig.getRemoteSignatureCredentialPassword()).thenReturn("pwd");

        SignatureRequest req = new SignatureRequest(
                new SignatureConfiguration(SignatureType.JADES, Map.of()),
                "{\"a\":1}"
        );

        // 1) access token (from QtspAuthClient)
        when(qtspAuthClient.requestAccessToken(eq(req), eq(SIGNATURE_REMOTE_SCOPE_CREDENTIAL)))
                .thenReturn(Mono.just("access-token"));

        // 2) SAD
        when(httpUtils.postRequest(eq("https://api.external.com/csc/v2/credentials/authorize"), anyList(), anyString()))
                .thenReturn(Mono.just("{\"SAD\":\"sad-123\"}"));
        when(objectMapper.readValue(eq("{\"SAD\":\"sad-123\"}"), eq(Map.class)))
                .thenReturn(Map.of("SAD", "sad-123"));

        // 3) signDoc
        String jwtOrJades = "signed-jwt";
        String base64Signed = Base64.getEncoder().encodeToString(jwtOrJades.getBytes(StandardCharsets.UTF_8));
        String signDocResponse = "{\"DocumentWithSignature\":[\"" + base64Signed + "\"]}";

        when(httpUtils.postRequest(eq("https://api.external.com/csc/v2/signatures/signDoc"), anyList(), anyString()))
                .thenReturn(Mono.just(signDocResponse));
        when(objectMapper.readValue(eq(signDocResponse), eq(Map.class)))
                .thenReturn(Map.of("DocumentWithSignature", List.of(base64Signed)));

        // processSignatureResponse compares payloads
        when(jwtUtils.decodePayload(jwtOrJades)).thenReturn("{\"a\":1}");
        when(jwtUtils.areJsonsEqual(eq("{\"a\":1}"), eq(req.data()))).thenReturn(true);

        // final JSON that executeSigningFlow parses to SignedData
        String signedDataJson = "{\"type\":\"JADES\",\"data\":\"" + jwtOrJades + "\"}";
        when(objectMapper.writeValueAsString(any(Map.class))).thenReturn(signedDataJson);
        SignedData expected = new SignedData(SignatureType.JADES, jwtOrJades);
        when(objectMapper.readValue(signedDataJson, SignedData.class)).thenReturn(expected);

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

        SignatureRequest req = new SignatureRequest(
                new SignatureConfiguration(SignatureType.JADES, Map.of()),
                "{\"a\":1}"
        );

        when(qtspAuthClient.requestAccessToken(eq(req), eq(SIGNATURE_REMOTE_SCOPE_CREDENTIAL)))
                .thenReturn(Mono.just("access-token"));

        when(httpUtils.postRequest(
                eq("https://api.external.com/csc/v2/credentials/authorize"),
                anyList(),
                isNull()
        )).thenReturn(Mono.just("{\"NO_SAD\":\"x\"}"));

        when(objectMapper.readValue(eq("{\"NO_SAD\":\"x\"}"), eq(Map.class)))
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
        SignatureRequest req = new SignatureRequest(
                new SignatureConfiguration(SignatureType.JADES, Map.of()),
                "{\"a\":1}"
        );

        String responseJson = "{\"DocumentWithSignature\":[]}";
        when(objectMapper.readValue(eq(responseJson), eq(Map.class)))
                .thenReturn(Map.of("DocumentWithSignature", List.of()));

        StepVerifier.create(remoteSignatureService.processSignatureResponse(req, responseJson))
                .expectError(SignatureProcessingException.class)
                .verify();
    }

    @Test
    void processSignatureResponse_shouldFail_whenPayloadMismatch() throws Exception {
        SignatureRequest req = new SignatureRequest(
                new SignatureConfiguration(SignatureType.JADES, Map.of()),
                "{\"a\":1}"
        );

        String signedJwt = "signed-jwt";
        String base64Signed = Base64.getEncoder().encodeToString(signedJwt.getBytes(StandardCharsets.UTF_8));
        String responseJson = "{\"DocumentWithSignature\":[\"" + base64Signed + "\"]}";

        when(objectMapper.readValue(eq(responseJson), eq(Map.class)))
                .thenReturn(Map.of("DocumentWithSignature", List.of(base64Signed)));

        // decodePayload returns something different
        when(jwtUtils.decodePayload(signedJwt)).thenReturn("{\"a\":999}");
        when(jwtUtils.areJsonsEqual(eq("{\"a\":999}"), eq(req.data()))).thenReturn(false);

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

        SignatureRequest req = new SignatureRequest(
                new SignatureConfiguration(SignatureType.JADES, Map.of()),
                "{\"a\":1}"
        );

        when(qtspAuthClient.requestAccessToken(eq(req), eq(SIGNATURE_REMOTE_SCOPE_CREDENTIAL)))
                .thenReturn(Mono.just("access-token"));

        when(httpUtils.postRequest(eq("https://api.external.com/csc/v2/credentials/authorize"), anyList(), anyString()))
                .thenReturn(Mono.just("{\"SAD\":\"sad-123\"}"));
        when(objectMapper.readValue(eq("{\"SAD\":\"sad-123\"}"), eq(Map.class)))
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

        // fail twice then succeed (retry)
        when(httpUtils.postRequest(eq("https://api.external.com/csc/v2/signatures/signDoc"), anyList(), anyString()))
                .thenReturn(Mono.error(serverError), Mono.error(serverError), Mono.just(signDocResponse));

        when(objectMapper.readValue(eq(signDocResponse), eq(Map.class)))
                .thenReturn(Map.of("DocumentWithSignature", List.of(base64Signed)));

        when(jwtUtils.decodePayload(jwtOrJades)).thenReturn("{\"a\":1}");
        when(jwtUtils.areJsonsEqual(eq("{\"a\":1}"), eq(req.data()))).thenReturn(true);

        String signedDataJson = "{\"type\":\"JADES\",\"data\":\"" + jwtOrJades + "\"}";
        when(objectMapper.writeValueAsString(any(Map.class))).thenReturn(signedDataJson);

        SignedData expected = new SignedData(SignatureType.JADES, jwtOrJades);
        when(objectMapper.readValue(signedDataJson, SignedData.class)).thenReturn(expected);

        StepVerifier.create(remoteSignatureService.signIssuedCredential(req, "token", "proc-1", "mail"))
                .expectNext(expected)
                .verifyComplete();

        // token+sad+signDoc were attempted multiple times due to retry
        verify(httpUtils, times(3)).postRequest(eq("https://api.external.com/csc/v2/signatures/signDoc"), anyList(), anyString());
        verify(deferredCredentialMetadataService).deleteDeferredCredentialMetadataById("proc-1");
    }
}
