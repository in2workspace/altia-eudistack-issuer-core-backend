package es.in2.issuer.backend.signing.infrastructure.properties;

import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "issuer.signing.csc")
@Validated
public record CscSigningProperties(
        JadesProfile signatureProfile
) {
    public CscSigningProperties {
        if (signatureProfile == null) signatureProfile = JadesProfile.JADES_B_T; // default recomendado
    }
}