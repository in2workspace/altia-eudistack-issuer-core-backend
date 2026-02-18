package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.model.SigningContext;
import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class InMemorySigningProviderTest {

    @InjectMocks
    private InMemorySigningProvider provider;

    @Test
    void signReturnsJwsLikeStringForJades() {
        String payloadJson = "{\"foo\":\"bar\"}";
        SigningContext ctx = new SigningContext ("token","proc","email");

        SigningRequest req = new SigningRequest(SigningType.JADES, payloadJson, ctx);

        StepVerifier.create(provider.sign(req))
                .assertNext(res -> {
                    assertEquals(SigningType.JADES, res.type());

                    String jws = res.data();
                    assertNotNull(jws);

                    String[] parts = jws.split("\\.", -1);
                    assertEquals(3, parts.length);
                    assertTrue(parts[2].isEmpty());

                    String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
                    String decodedPayload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

                    assertTrue(headerJson.contains("\"alg\":\"none\""));
                    assertTrue(headerJson.contains("\"typ\":\"JWT\""));
                    assertEquals(payloadJson, decodedPayload);
                })
                .verifyComplete();
    }


    @Test
    void signReturnsBase64ForCose() {
        SigningContext context = new SigningContext("token", "proc", "email");
        String base64 = java.util.Base64.getEncoder().encodeToString("cborbytes".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        SigningRequest request = new SigningRequest(SigningType.COSE, base64, context);
        StepVerifier.create(provider.sign(request))
                .assertNext(result -> {
                    assert result.type() == SigningType.COSE;
                    assert result.data().equals(base64);
                })
                .verifyComplete();
    }

    @Test
    void signThrowsSigningExceptionOnNullRequest() {
        StepVerifier.create(provider.sign(null))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullType() {
        SigningContext context = new SigningContext("token", "proc", "email");
        SigningRequest request = new SigningRequest(null, "data", context);
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullData() {
        SigningContext context = new SigningContext("token", "proc", "email");
        SigningRequest request = new SigningRequest(SigningType.JADES, null, context);
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnBlankData() {
        SigningContext context = new SigningContext("token", "proc", "email");
        SigningRequest request = new SigningRequest(SigningType.JADES, "   ", context);
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullContext() {
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", null);
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullToken() {
        SigningContext context = new SigningContext(null, "proc", "email");
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", context);
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnBlankToken() {
        SigningContext context = new SigningContext("   ", "proc", "email");
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", context);
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }
}
