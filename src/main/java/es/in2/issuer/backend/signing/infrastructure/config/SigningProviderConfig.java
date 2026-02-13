package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignDocSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.InMemorySigningProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class SigningProviderConfig {

    /**
     * Allowed values (core-only PR2):
     * - in-memory
     * - csc-sign-doc
     *
     * Values reserved for future Enterprise implementations:
     * - csc-sign-hash
     */
    @Value("${issuer.signing.provider:remote}")
    private String provider;

    private final InMemorySigningProvider inMemorySigningProvider;
    private final CscSignDocSigningProvider cscSignDocSigningProvider;

    @Bean
    public SigningProvider signingProvider() {
        String normalized = normalize(provider);

        return switch (normalized) {
            case "in-memory" -> {
                log.info("SigningProvider selected: in-memory");
                yield inMemorySigningProvider;
            }
            case "csc-sign-doc" -> {
                log.info("SigningProvider selected: csc-sign-doc");
                yield cscSignDocSigningProvider;
            }

            //TODO: Remove when csc-sign-hash provider is implemented.
            case "csc-sign-hash" -> throw new IllegalStateException(
                    "Signing provider '" + provider + "' must be provided by Enterprise module. " +
                            "Core-only build supports: in-memory, csc-sign-doc"
            );

            default -> throw new IllegalStateException(
                    "Unknown signing provider '" + provider + "'. " +
                            "Supported providers (core-only): in-memory, csc-sign-doc"
            );
        };
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase();
    }
}

