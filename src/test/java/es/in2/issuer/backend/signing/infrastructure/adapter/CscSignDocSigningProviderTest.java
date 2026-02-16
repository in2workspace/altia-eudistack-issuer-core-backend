package es.in2.issuer.backend.signing.infrastructure.adapter;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningContext;
import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.SigningType;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CscSignDocSigningProviderTest {
    @Mock
    private RemoteSignatureService remoteSignatureService;

    @InjectMocks
    private CscSignDocSigningProvider cscSignDocSigningProvider;

    @Test
    void signReturnsSigningResultOnSuccess() {
        SigningContext context = new SigningContext("token", "procedureId", "email@example.com");
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", context);
        SignedData signedData = new SignedData(SignatureType.JADES, "signedData");
        when(remoteSignatureService.signIssuedCredential(any(SignatureRequest.class), eq("token"), eq("procedureId"), eq("email@example.com")))
                .thenReturn(Mono.just(signedData));
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .assertNext(result -> {
                    assertThat(result.type()).isEqualTo(SigningType.JADES);
                    assertThat(result.data()).isEqualTo("signedData");
                })
                .verifyComplete();
    }

    @Test
    void signThrowsSigningExceptionOnNullRequest() {
        StepVerifier.create(cscSignDocSigningProvider.sign(null))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullType() {
        SigningContext context = new SigningContext("token", "procedureId", "email@example.com");
        SigningRequest request = new SigningRequest(null, "data", context);
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullContext() {
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", null);
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signPropagatesRemoteSignatureServiceError() {
        SigningContext context = new SigningContext("token", "procedureId", "email@example.com");
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", context);
        when(remoteSignatureService.signIssuedCredential(any(SignatureRequest.class), eq("token"), eq("procedureId"), eq("email@example.com")))
                .thenReturn(Mono.error(new RuntimeException("remote error")));
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }


    private static Object[][] invalidRequests() {
        SigningContext validContext = new SigningContext("token", "procedureId", "email@example.com");
        return new Object[][]{
                {null, "Null request"},
                {new SigningRequest(null, "data", validContext), "Null type"},
                {new SigningRequest(SigningType.JADES, null, validContext), "Null data"},
                {new SigningRequest(SigningType.JADES, "   ", validContext), "Blank data"},
                {new SigningRequest(SigningType.JADES, "data", null), "Null context"},
                {new SigningRequest(SigningType.JADES, "data", new SigningContext(null, "procedureId", "email@example.com")), "Null token"},
                {new SigningRequest(SigningType.JADES, "data", new SigningContext("   ", "procedureId", "email@example.com")), "Blank token"}
        };
    }

    @ParameterizedTest(name = "{index}: {1}")
    @MethodSource("invalidRequests")
    void signThrowsSigningExceptionOnInvalidRequest(SigningRequest request, String description) {
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

}
