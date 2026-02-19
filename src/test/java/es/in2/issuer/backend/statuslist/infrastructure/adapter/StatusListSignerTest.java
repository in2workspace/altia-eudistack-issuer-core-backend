package es.in2.issuer.backend.statuslist.infrastructure.adapter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.statuslist.domain.exception.StatusListCredentialSerializationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.Method;
import java.util.Map;

import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;

@ExtendWith(MockitoExtension.class)
class StatusListSignerTest {

    @Mock
    private SigningProvider signingProvider;

    @Mock
    private ObjectMapper objectMapper;

    @Captor
    private ArgumentCaptor<SigningRequest> signingRequestCaptor;

    @Test
    void sign_shouldReturnJwt_whenSigningProviderSucceeds() throws Exception {
        // Arrange
        StatusListSigner signer = new StatusListSigner(signingProvider, objectMapper);

        Map<String, Object> payload = Map.of("id", "abc", "foo", "bar");
        String token = "token-123";
        Long listId = 99L;

        String json = "{\"id\":\"abc\",\"foo\":\"bar\"}";
        when(objectMapper.writeValueAsString(payload)).thenReturn(json);

        SigningResult signingResult = mock(SigningResult.class);
        when(signingResult.data()).thenReturn("jwt-value");

        when(signingProvider.sign(any()))
                .thenReturn(Mono.just(signingResult));

        // Act + Assert
        StepVerifier.create(signer.sign(payload, token, listId))
                .expectNext("jwt-value")
                .verifyComplete();

        // Verify request contents (light but useful checks)
        verify(signingProvider, times(1)).sign(signingRequestCaptor.capture());
        SigningRequest req = signingRequestCaptor.getValue();

        Object typeValue = readProperty(req, "type");
        assertThat(typeValue).hasToString("JADES");

        Object dataValue = readProperty(req, "data");
        assertThat(dataValue).isEqualTo(json);

    }

    @Test
    void sign_shouldWrapProviderErrorsIntoSigningException_withListId() throws Exception {
        // Arrange
        StatusListSigner signer = new StatusListSigner(signingProvider, objectMapper);

        Map<String, Object> payload = Map.of("a", 1);
        String token = "t";
        Long listId = 123L;

        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"a\":1}");

        RuntimeException providerError = new RuntimeException("boom");
        when(signingProvider.sign(any()))
                .thenReturn(Mono.error(providerError));

        // Act + Assert
        StepVerifier.create(signer.sign(payload, token, listId))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(RemoteSignatureException.class);
                    assertThat(ex.getMessage()).isEqualTo("Remote signature failed; list ID: " + listId);
                    assertThat(ex.getCause()).isSameAs(providerError);
                })
                .verify();
    }

    @Test
    void sign_shouldWrapSerializationErrorIntoSigningException_andKeepCauseChain() throws Exception {
        // Arrange
        StatusListSigner signer = new StatusListSigner(signingProvider, objectMapper);

        Map<String, Object> payload = Map.of("a", 1);
        String token = "t";
        Long listId = 777L;

        JsonProcessingException jacksonEx = new JsonProcessingException("json fail") {};
        when(objectMapper.writeValueAsString(payload)).thenThrow(jacksonEx);

        // Act + Assert
        StepVerifier.create(signer.sign(payload, token, listId))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(RemoteSignatureException.class);
                    assertThat(ex.getMessage()).isEqualTo("Remote signature failed; list ID: " + listId);

                    assertThat(ex.getCause()).isInstanceOf(StatusListCredentialSerializationException.class);
                    assertThat(ex.getCause().getCause()).isSameAs(jacksonEx);
                })
                .verify();

        verifyNoInteractions(signingProvider);
    }

    @Test
    void sign_shouldErrorWhenSignerReturnsEmptyJwt() throws Exception {
        // Arrange
        StatusListSigner signer = new StatusListSigner(signingProvider, objectMapper);

        Map<String, Object> payload = Map.of("a", 1);
        String token = "t";
        Long listId = 5L;

        when(objectMapper.writeValueAsString(payload)).thenReturn("{\"a\":1}");

        SigningResult signingResult = mock(SigningResult.class);
        when(signingResult.data()).thenReturn("   ");

        when(signingProvider.sign(any()))
                .thenReturn(Mono.just(signingResult));

        // Act + Assert
        StepVerifier.create(signer.sign(payload, token, listId))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(RemoteSignatureException.class);
                    assertThat(ex.getMessage()).isEqualTo("Signed returned empty signingResult; list ID: " + listId);
                    assertThat(ex.getCause()).isNull();
                })
                .verify();
    }

    @Test
    void sign_shouldThrowImmediately_whenPayloadIsNull() {
        StatusListSigner signer = new StatusListSigner(signingProvider, objectMapper);
        assertThrows(RuntimeException.class, () -> signer.sign(null, "token", 1L));
    }

    @Test
    void sign_shouldThrowImmediately_whenTokenIsNull() {
        StatusListSigner signer = new StatusListSigner(signingProvider, objectMapper);

        assertThatThrownBy(() -> signer.sign(Map.of("a", 1), null, 1L))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("token");
    }

    /**
     * Reads a property from either:
     * - a Java record component accessor (e.g. data())
     * - a standard getter (e.g. getData())
     */
    private static Object readProperty(Object target, String property) {
        try {
            return tryRecordStyleAccess(target, property);
        } catch (NoSuchMethodException ignored) {
            return tryBeanStyleAccess(target, property);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Object tryRecordStyleAccess(Object target, String property) throws Exception {
        Method recordStyle = target.getClass().getMethod(property);
        return recordStyle.invoke(target);
    }

    private static Object tryBeanStyleAccess(Object target, String property) {
        String getter = "get" + Character.toUpperCase(property.charAt(0)) + property.substring(1);
        try {
            Method beanStyle = target.getClass().getMethod(getter);
            return beanStyle.invoke(target);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
