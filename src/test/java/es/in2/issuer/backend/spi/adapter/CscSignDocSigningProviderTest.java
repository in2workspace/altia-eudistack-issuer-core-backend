package es.in2.issuer.backend.spi.adapter;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.shared.domain.model.dto.SignedData;
import es.in2.issuer.backend.shared.domain.model.enums.SignatureType;
import es.in2.issuer.backend.shared.domain.service.RemoteSignatureService;

import es.in2.issuer.backend.spi.domain.exception.SigningException;
import es.in2.issuer.backend.spi.domain.model.SigningContext;
import es.in2.issuer.backend.spi.domain.model.SigningRequest;
import es.in2.issuer.backend.spi.domain.model.SigningType;
import es.in2.issuer.backend.spi.infrastructure.adapter.CscSignDocSigningProvider;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CscSignDocSigningProviderTest {
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
                    assertThat(SigningType.JADES).isEqualTo(result.type());
                    assertThat("signedData").isEqualTo(result.data());
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
    void signThrowsSigningExceptionOnNullData() {
        SigningContext context = new SigningContext("token", "procedureId", "email@example.com");
        SigningRequest request = new SigningRequest(SigningType.JADES, null, context);
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnBlankData() {
        SigningContext context = new SigningContext("token", "procedureId", "email@example.com");
        SigningRequest request = new SigningRequest(SigningType.JADES, "   ", context);
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
    void signThrowsSigningExceptionOnNullToken() {
        SigningContext context = new SigningContext(null, "procedureId", "email@example.com");
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", context);
        StepVerifier.create(cscSignDocSigningProvider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnBlankToken() {
        SigningContext context = new SigningContext("   ", "procedureId", "email@example.com");
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", context);
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

}
