package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignDocSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.InMemorySigningProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SigningProviderConfigTest {

    @Mock
    private InMemorySigningProvider inMemorySigningProvider;

    @Mock
    private CscSignDocSigningProvider cscSignDocSigningProvider;

    @InjectMocks
    private SigningProviderConfig config;

    @BeforeEach
    void setup() {
        config = new SigningProviderConfig(inMemorySigningProvider, cscSignDocSigningProvider);
    }

    @Test
    void signingProvider_returnsInMemory_whenProviderIsInMemory() {
        ReflectionTestUtils.setField(config, "provider", "in-memory");
        SigningProvider provider = config.signingProvider();
        assertEquals(inMemorySigningProvider, provider);
    }

    @Test
    void signingProvider_returnsCscSignDoc_whenProviderIsCscSignDoc() {
        ReflectionTestUtils.setField(config, "provider", "csc-sign-doc");
        SigningProvider provider = config.signingProvider();
        assertEquals(cscSignDocSigningProvider, provider);
    }

    @Test
    void signingProvider_throwsOnCscSignHash() {
        ReflectionTestUtils.setField(config, "provider", "csc-sign-hash");

        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> config.signingProvider()
        );

        assertTrue(ex.getMessage().contains("must be provided by Enterprise module"));
    }

    @Test
    void signingProvider_throwsOnUnknownProvider() {
        ReflectionTestUtils.setField(config, "provider", "unknown");

        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> config.signingProvider()
        );

        assertTrue(ex.getMessage().contains("Unknown signing provider"));
    }

    @Test
    void normalize_trimsAndLowercases() {
        String normalized = ReflectionTestUtils.invokeMethod(
                SigningProviderConfig.class,
                "normalize",
                new Object[]{"  CSC-SIGN-DOC  "}
        );

        String normalizedNull = ReflectionTestUtils.invokeMethod(
                SigningProviderConfig.class,
                "normalize",
                new Object[]{null}
        );

        assertEquals("csc-sign-doc", normalized);
        assertEquals("", normalizedNull);
    }
}
