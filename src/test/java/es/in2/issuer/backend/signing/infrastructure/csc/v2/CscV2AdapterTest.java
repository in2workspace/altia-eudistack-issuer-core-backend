package es.in2.issuer.backend.signing.infrastructure.csc.v2;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.infrastructure.util.HttpUtils;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.auth.CscAuthStrategy;
import es.in2.issuer.backend.signing.infrastructure.csc.auth.CscAuthStrategyResolver;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.infrastructure.csc.v2.mapper.CscV2CertificateInfoMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CscV2AdapterTest {

    @Mock private CscAuthStrategyResolver authStrategyResolver;
    @Mock private CscV2CertificateInfoMapper certificateInfoMapper;
    @Mock private HttpUtils httpUtils;

    private CscV2Adapter adapter;
    private RemoteSignatureDto cfg;

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = new ObjectMapper();
        adapter = new CscV2Adapter(authStrategyResolver, certificateInfoMapper, objectMapper, httpUtils);

        cfg = new RemoteSignatureDto(
                "oauth2",
                "v2",
                "https://qtsp.test",
                "https://qtsp.test",
                "sign-hash",
                "cred-123", "pwd",
                "PT10M",
                "clientId", "clientSecret",
                "",
                "",
                "",
                "",
                ""
        );
    }

    @Test
    void authorizeForHash_success_returnsSad() {
        when(httpUtils.postRequest(
                eq("https://qtsp.test" + CscV2Paths.AUTHORIZE),
                anyList(),
                anyString()
        )).thenReturn(Mono.just("{\"SAD\":\"sad-token-123\"}"));

        StepVerifier.create(adapter.authorizeForHash(cfg, "access-token", "hashB64Url", "2.16.840.1.101.3.4.2.1"))
                .expectNext("sad-token-123")
                .verifyComplete();
    }

    @Test
    void authorizeForHash_emptySad_shouldError() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{}"));

        StepVerifier.create(adapter.authorizeForHash(cfg, "access-token", "hashB64Url", "2.16.840.1.101.3.4.2.1"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Empty authorize response"));
                })
                .verify();
    }

    @Test
    void authorizeForHash_unauthorized_mapsToRemoteSignatureException() {
        WebClientResponseException unauthorized = WebClientResponseException.create(
                HttpStatus.UNAUTHORIZED.value(), "Unauthorized", null,
                new byte[0], StandardCharsets.UTF_8
        );

        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.error(unauthorized));

        StepVerifier.create(adapter.authorizeForHash(cfg, "access-token", "hashB64Url", "2.16.840.1.101.3.4.2.1"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Unauthorized on credentials/authorize (hash)"));
                })
                .verify();
    }

    @Test
    void signHash_success_returnsFirstSignature() {
        when(httpUtils.postRequest(
                eq("https://qtsp.test" + CscV2Paths.SIGN_HASH),
                anyList(),
                anyString()
        )).thenReturn(Mono.just("{\"signatures\":[\"sig-abc\"]}"));

        StepVerifier.create(adapter.signHash(cfg, "access-token", "sad-1", "hashB64Url",
                        "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2"))
                .expectNext("sig-abc")
                .verifyComplete();
    }

    @Test
    void signHash_missingSignatures_shouldError() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{\"signatures\":[]}"));

        StepVerifier.create(adapter.signHash(cfg, "access-token", "sad-1", "hashB64Url",
                        "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("signHash response missing signatures[0]"));
                })
                .verify();
    }

    @Test
    void signHash_unauthorized_mapsToRemoteSignatureException() {
        WebClientResponseException unauthorized = WebClientResponseException.create(
                HttpStatus.UNAUTHORIZED.value(), "Unauthorized", null,
                new byte[0], StandardCharsets.UTF_8
        );

        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.error(unauthorized));

        StepVerifier.create(adapter.signHash(cfg, "access-token", "sad-1", "hashB64Url",
                        "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Unauthorized on signatures/signHash"));
                })
                .verify();
    }

    @Test
    void authorizeForDoc_success_returnsSad() {
        when(httpUtils.postRequest(
                eq("https://qtsp.test" + CscV2Paths.AUTHORIZE),
                anyList(),
                anyString()
        )).thenReturn(Mono.just("{\"SAD\":\"doc-sad-456\"}"));

        StepVerifier.create(adapter.authorizeForDoc(cfg, "access-token"))
                .expectNext("doc-sad-456")
                .verifyComplete();
    }

    @Test
    void authorizeForDoc_emptySad_shouldError() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{}"));

        StepVerifier.create(adapter.authorizeForDoc(cfg, "access-token"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Empty authorize response"));
                })
                .verify();
    }

    @Test
    void signDoc_success_returnsFirstDocument() {
        String docB64 = "c2lnbmVk";
        when(httpUtils.postRequest(
                eq("https://qtsp.test" + CscV2Paths.SIGN_DOC),
                anyList(),
                anyString()
        )).thenReturn(Mono.just("{\"DocumentWithSignature\":[\"" + docB64 + "\"]}"));

        StepVerifier.create(adapter.signDoc(cfg, "access-token", "sad-1", "rawDocB64", "1.2.840.10045.4.3.2"))
                .expectNext(docB64)
                .verifyComplete();
    }

    @Test
    void signDoc_missingDocument_shouldError() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{\"DocumentWithSignature\":[]}"));

        StepVerifier.create(adapter.signDoc(cfg, "access-token", "sad-1", "rawDocB64", "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> assertTrue(ex instanceof RemoteSignatureException))
                .verify();
    }

    @Test
    void getCredentialInfo_success_returnsMappedCertInfo() {
        CertificateInfo expected = new CertificateInfo(
                List.of("MIIC..."), "CN=CA", "CN=Test,O=Org,C=ES", "123",
                "2024-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
                List.of("1.2.840.10045.4.3.2"), 256, false
        );

        when(httpUtils.postRequest(
                eq("https://qtsp.test" + CscV2Paths.INFO),
                anyList(),
                anyString()
        )).thenReturn(Mono.just("{\"key\":{},\"cert\":{}}"));
        when(certificateInfoMapper.map(anyMap())).thenReturn(expected);

        StepVerifier.create(adapter.getCredentialInfo(cfg, "access-token", "cred-123"))
                .expectNext(expected)
                .verifyComplete();
    }

    @Test
    void validateCredentialId_returnsTrueWhenPresent() {
        when(httpUtils.postRequest(
                eq("https://qtsp.test" + CscV2Paths.LIST),
                anyList(),
                anyString()
        )).thenReturn(Mono.just("{\"credentialIDs\":[\"cred-123\"]}"));

        StepVerifier.create(adapter.validateCredentialId(cfg, "access-token", "cred-123"))
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    void validateCredentialId_returnsFalseWhenAbsent() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{\"credentialIDs\":[\"OTHER\"]}"));

        StepVerifier.create(adapter.validateCredentialId(cfg, "access-token", "cred-123"))
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    void listCredentialIds_returnsIds() {
        when(httpUtils.postRequest(
                eq("https://qtsp.test" + CscV2Paths.LIST),
                anyList(),
                anyString()
        )).thenReturn(Mono.just("{\"credentialIDs\":[\"id-1\",\"id-2\"]}"));

        StepVerifier.create(adapter.listCredentialIds(cfg, "access-token"))
                .assertNext(ids -> assertTrue(ids.containsAll(List.of("id-1", "id-2"))))
                .verifyComplete();
    }

    // A QTSP's credentials/list returning a raw 500 (e.g. Digitel rejecting a
    // spec-conformant request body) must not propagate as-is: it has to
    // surface as a RemoteSignatureException, which SharedExceptionHandler
    // maps to 502 Bad Gateway — see SharedExceptionHandlerTest#handleRemoteSignatureException.
    @Test
    void validateCredentialId_qtspInternalServerError_mapsToRemoteSignatureException() {
        WebClientResponseException internalServerError = WebClientResponseException.create(
                HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal Server Error", null,
                new byte[0], StandardCharsets.UTF_8
        );

        when(httpUtils.postRequest(
                eq("https://qtsp.test" + CscV2Paths.LIST),
                anyList(),
                anyString()
        )).thenReturn(Mono.error(internalServerError));

        StepVerifier.create(adapter.validateCredentialId(cfg, "access-token", "cred-123"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Failed to list credentials from url"));
                })
                .verify();
    }

    @Test
    void listCredentialIds_qtspInternalServerError_mapsToRemoteSignatureException() {
        WebClientResponseException internalServerError = WebClientResponseException.create(
                HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal Server Error", null,
                new byte[0], StandardCharsets.UTF_8
        );

        when(httpUtils.postRequest(
                eq("https://qtsp.test" + CscV2Paths.LIST),
                anyList(),
                anyString()
        )).thenReturn(Mono.error(internalServerError));

        StepVerifier.create(adapter.listCredentialIds(cfg, "access-token"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Failed to list credentials"));
                })
                .verify();
    }

    @Test
    void requestAccessToken_delegatesToAuthStrategy() {
        CscAuthStrategy mockStrategy = mock(CscAuthStrategy.class);
        when(authStrategyResolver.resolveFromValue("oauth2")).thenReturn(mockStrategy);
        when(mockStrategy.requestAccessToken(any(), anyString(), anyBoolean()))
                .thenReturn(Mono.just("delegated-token"));

        StepVerifier.create(adapter.requestAccessToken(cfg, "scope", false, null))
                .expectNext("delegated-token")
                .verifyComplete();
    }
}
