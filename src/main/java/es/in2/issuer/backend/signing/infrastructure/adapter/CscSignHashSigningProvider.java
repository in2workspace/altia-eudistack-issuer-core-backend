package es.in2.issuer.backend.signing.infrastructure.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;

@Slf4j
@Service
@RequiredArgsConstructor
public class CscSignHashSigningProvider implements SigningProvider {

    private final QtspAuthClient qtspAuthClient;
    private final QtspIssuerService qtspIssuerService;
    private final JwsSignHashService jwsSignHashService;
    private final JadesHeaderBuilderService jadesHeaderBuilder;
    private final CscSigningProperties cscSigningProperties;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            SigningRequestValidator.validate(request, false);

            if (request.type() != SigningType.JADES) {
                return Mono.error(new SigningException("csc-sign-hash supports only JADES/JWT"));
            }

            JadesProfile profile = cscSigningProperties.signatureProfile();

            return qtspAuthClient.requestAccessToken(request, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false)
                    .flatMap(accessToken ->
                            qtspIssuerService.requestCertificateInfo(accessToken, qtspIssuerService.getCredentialId())
                                    .flatMap(this::parseJsonToMap)
                                    .map(this::mapToCertificateInfo)
                                    .flatMap(certInfo -> {
                                        String headerJson = jadesHeaderBuilder.buildHeader(certInfo, profile);
                                        return jwsSignHashService.signJwtWithSignHash(accessToken, headerJson, request.data());
                                    })
                    )
                    .map(jwt -> new SigningResult(SigningType.JADES, jwt))
                    .onErrorMap(ex -> (ex instanceof SigningException) ? ex
                            : new SigningException("Signing failed via CSC signHash provider: " + ex.getMessage(), ex));
        });
    }


    private Mono<Map<String, Object>> parseJsonToMap(String json) {
        return Mono.fromCallable(() ->
                objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {})
        ).onErrorMap(ex -> new SigningException("Invalid QTSP certificateInfo JSON: " + ex.getMessage(), ex));
    }

    private CertificateInfo mapToCertificateInfo(Map<String, Object> response) {

        if (response == null) {
            throw new IllegalStateException("CSC credentials/info response is null");
        }

        Map<String, Object> key = (Map<String, Object>) response.get("key");
        if (key == null) {
            throw new IllegalStateException("Missing 'key' section in CSC response");
        }

        String keyStatus = (String) key.get("status");
        if (!"enabled".equalsIgnoreCase(keyStatus)) {
            throw new IllegalStateException("Signing key is not enabled: " + keyStatus);
        }

        List<String> keyAlgorithms = (List<String>) key.get("algo");
        if (keyAlgorithms == null || keyAlgorithms.isEmpty()) {
            throw new IllegalStateException("No signing algorithm returned by QTSP");
        }

        Integer keyLength = (Integer) key.get("len");

        Map<String, Object> cert = (Map<String, Object>) response.get("cert");
        if (cert == null) {
            throw new IllegalStateException("Missing 'cert' section in CSC response");
        }

        String certStatus = (String) cert.get("status");
        if (!"valid".equalsIgnoreCase(certStatus)) {
            throw new IllegalStateException("Certificate is not valid: " + certStatus);
        }

        List<String> certificates = (List<String>) cert.get("certificates");
        if (certificates == null || certificates.isEmpty()) {
            throw new IllegalStateException("No certificate chain returned by QTSP");
        }

        String issuerDN = (String) cert.get("issuerDN");
        String subjectDN = (String) cert.get("subjectDN");
        String serialNumber = (String) cert.get("serialNumber");
        String validFrom = (String) cert.get("validFrom");
        String validTo = (String) cert.get("validTo");

        return new CertificateInfo(
                certificates,
                issuerDN,
                subjectDN,
                serialNumber,
                validFrom,
                validTo,
                keyAlgorithms,
                keyLength
        );
    }
}
