package es.in2.issuer.backend.oidc4vci.infrastructure.config;

import es.in2.issuer.backend.oidc4vci.domain.model.port.Oid4vciProfilePort;
import es.in2.issuer.backend.shared.domain.util.Constants;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "oid4vci.profile")
public record Oid4vciProfileProperties(
        List<String> grantsSupported,
        AuthorizationCodeProperties authorizationCode
) implements Oid4vciProfilePort {

    public record AuthorizationCodeProperties(
            boolean requirePar,
            boolean requirePkce,
            List<String> pkceMethods,
            boolean requireDpop,
            List<String> dpopSigningAlgs,
            String clientAuthMethod,
            boolean requireNonce
    ) implements Oid4vciProfilePort.AuthorizationCodeConfig {
        public AuthorizationCodeProperties {
            if (pkceMethods == null) pkceMethods = List.of("S256");
            if (dpopSigningAlgs == null) dpopSigningAlgs = List.of("ES256");
            if (clientAuthMethod == null) clientAuthMethod = "none";
        }
    }

    public Oid4vciProfileProperties {
        if (grantsSupported == null) grantsSupported = List.of(Constants.GRANT_TYPE);
        if (authorizationCode == null) authorizationCode = new AuthorizationCodeProperties(
                false, false, List.of("S256"), false, List.of("ES256"), "none", false
        );
    }

    public boolean isAuthorizationCodeEnabled() {
        return grantsSupported != null && grantsSupported.contains(Constants.AUTHORIZATION_CODE);
    }

    public boolean isPreAuthorizedCodeEnabled() {
        return grantsSupported != null &&
                grantsSupported.contains(Constants.GRANT_TYPE);
    }

    public boolean isHaipProfile() {
        return authorizationCode != null
                && authorizationCode.requirePar()
                && authorizationCode.requireDpop()
                && "attest_jwt_client_auth".equals(authorizationCode.clientAuthMethod());
    }
}
