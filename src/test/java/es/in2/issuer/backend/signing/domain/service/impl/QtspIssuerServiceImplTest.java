package es.in2.issuer.backend.signing.domain.service.impl;


import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.signing.domain.exception.OrganizationIdentifierNotFoundException;
import es.in2.issuer.backend.signing.infrastructure.config.RemoteSignatureConfig;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class QtspIssuerServiceImplTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private QtspIssuerServiceImpl qtspIssuerService;

    @Mock private QtspAuthClient qtspAuthClient;
    @Mock private RemoteSignatureConfig remoteSignatureConfig;
    @Mock private HttpUtils httpUtils;

    @BeforeEach
    void setUp() {
        qtspIssuerService = new QtspIssuerServiceImpl(
                objectMapper,
                qtspAuthClient,
                remoteSignatureConfig,
                httpUtils
        );
    }

    @Test
    void validateCredentials_returnsTrueWhenValid() {
        when(qtspAuthClient.requestAccessToken(any(SignatureRequest.class), anyString()))
                .thenReturn(Mono.just("token"));

        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("credId");
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://domain");

        when(httpUtils.postRequest(contains("/csc/v2/credentials/list"), any(), any()))
                .thenReturn(Mono.just("{\"credentialIDs\":[\"credId\"]}"));

        StepVerifier.create(qtspIssuerService.validateCredentials())
                .assertNext(valid -> assertThat(valid).isTrue())
                .verifyComplete();
    }

    @Test
    void validateCredentials_returnsFalseWhenInvalid() {
        when(qtspAuthClient.requestAccessToken(any(SignatureRequest.class), anyString()))
                .thenReturn(Mono.just("token"));

        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("credId");
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://domain");

        when(httpUtils.postRequest(contains("/csc/v2/credentials/list"), any(), any()))
                .thenReturn(Mono.just("{\"credentialIDs\":[\"OTHER\"]}"));

        StepVerifier.create(qtspIssuerService.validateCredentials())
                .assertNext(valid -> assertThat(valid).isFalse())
                .verifyComplete();
    }

    @Test
    void requestCertificateInfo_serializationError_returnsError() throws Exception {
        ObjectMapper failingMapper = mock(ObjectMapper.class);

        QtspIssuerServiceImpl service = new QtspIssuerServiceImpl(
                failingMapper, qtspAuthClient, remoteSignatureConfig, httpUtils
        );

        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://domain");

        doThrow(new JsonProcessingException("Error serializing request body to JSON") {})
                .when(failingMapper)
                .writeValueAsString(any());

        StepVerifier.create(service.requestCertificateInfo("token", "credId"))
                .expectErrorMatches(e -> e.getMessage().contains("Error serializing request body to JSON"))
                .verify();
    }


    @Test
    void extractIssuerFromCertificateInfo_successfulExtraction() {
        String base64Cert = Base64.getEncoder()
                .encodeToString("organizationIdentifier=ORGID".getBytes(StandardCharsets.UTF_8));

        String certInfo =
                "{ \"cert\": { " +
                        "\"subjectDN\":\"CN=Test,O=Org,C=ES\", " +
                        "\"serialNumber\":\"123\", " +
                        "\"certificates\":[\"" + base64Cert + "\"]" +
                        "} }";

        StepVerifier.create(qtspIssuerService.extractIssuerFromCertificateInfo(certInfo))
                .assertNext(issuer -> {
                    assertThat(issuer.organizationIdentifier()).isEqualTo("ORGID");
                    assertThat(issuer.id()).isEqualTo("did:elsi:ORGID");
                })
                .verifyComplete();
    }


    @Test
    void extractIssuerFromCertificateInfo_missingOrgId_returnsError() {
        String base64Cert = Base64.getEncoder()
                .encodeToString("no-org-here".getBytes(StandardCharsets.UTF_8));

        String certInfo =
                "{ \"cert\": { " +
                        "\"subjectDN\":\"CN=Test,O=Org,C=ES\", " +
                        "\"serialNumber\":\"123\", " +
                        "\"certificates\":[\"" + base64Cert + "\"]" +
                        "} }";

        StepVerifier.create(qtspIssuerService.extractIssuerFromCertificateInfo(certInfo))
                .expectError(OrganizationIdentifierNotFoundException.class)
                .verify();
    }


    @Test
    void isServerMode_returnsTrueWhenTypeIsServer() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn("server");
        assertThat(qtspIssuerService.isServerMode()).isTrue();
    }

    @Test
    void isServerMode_returnsFalseWhenTypeIsNotServer() {
        when(remoteSignatureConfig.getRemoteSignatureType()).thenReturn("other");
        assertThat(qtspIssuerService.isServerMode()).isFalse();
    }

    @Test
    void resolveRemoteDetailedIssuer_validCredentials_returnsIssuer() {
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("credId");
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://domain");

        when(qtspAuthClient.requestAccessToken(any(SignatureRequest.class), anyString()))
                .thenReturn(Mono.just("token-1"));
        when(qtspAuthClient.requestAccessToken(isNull(), anyString()))
                .thenReturn(Mono.just("token-2"));

        when(httpUtils.postRequest(contains("/csc/v2/credentials/list"), any(), any()))
                .thenReturn(Mono.just("{\"credentialIDs\":[\"credId\"]}"));

        String orgId = "ORGID";
        String base64Cert = Base64.getEncoder()
                .encodeToString(("organizationIdentifier=" + orgId).getBytes(StandardCharsets.UTF_8));

        String certInfoJson =
                "{ \"cert\": { " +
                        "\"subjectDN\": \"CN=Test,O=Org,C=ES\", " +
                        "\"serialNumber\": \"123\", " +
                        "\"certificates\": [\"" + base64Cert + "\"]" +
                        "} }";

        when(httpUtils.postRequest(contains("/csc/v2/credentials/info"), any(), any()))
                .thenReturn(Mono.just(certInfoJson));

        StepVerifier.create(qtspIssuerService.resolveRemoteDetailedIssuer())
                .assertNext(i -> {
                    assertThat(i.organizationIdentifier()).isEqualTo("ORGID");
                    assertThat(i.id()).isEqualTo("did:elsi:ORGID");
                    assertThat(i.organization()).isEqualTo("Org");
                    assertThat(i.country()).isEqualTo("ES");
                    assertThat(i.commonName()).isEqualTo("Test");
                    assertThat(i.serialNumber()).isEqualTo("123");
                })
                .verifyComplete();
    }


    @Test
    void resolveRemoteDetailedIssuer_invalidCredentials_returnsError() {
        when(qtspAuthClient.requestAccessToken(any(SignatureRequest.class), anyString()))
                .thenReturn(Mono.just("access-token"));

        when(httpUtils.postRequest(contains("/csc/v2/credentials/list"), anyList(), anyString()))
                .thenReturn(Mono.just("{\"credentialIDs\":[\"OTHER_ID\"]}"));
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("EXPECTED_ID");

        StepVerifier.create(qtspIssuerService.resolveRemoteDetailedIssuer())
                .expectErrorMatches(e -> e.getMessage().contains("Credentials mismatch"))
                .verify();
    }

}
