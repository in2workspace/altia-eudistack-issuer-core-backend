package es.in2.issuer.backend.signing.domain.service.impl;

import java.util.*;
import es.in2.issuer.backend.shared.domain.exception.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import es.in2.issuer.backend.signing.domain.exception.OrganizationIdentifierNotFoundException;
import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.infrastructure.config.RemoteSignatureConfig;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class QtspIssuerServiceImpl implements QtspIssuerService {

    private final ObjectMapper objectMapper;
    private final QtspAuthClient qtspAuthClient;
    private final RemoteSignatureConfig remoteSignatureConfig;
    private final HttpUtils httpUtils;

    private static final String CERTIFICATES = "certificates";
    private static final String CERT_INFO = "certInfo";
    private static final String AUTH_INFO = "authInfo";
    private static final String CREDENTIAL_INFO = "credentialInfo";
    private static final String ONLY_VALID = "onlyValid";
    private static final String LANG = "lang";
    private static final String CLIENT_DATA = "clientData";
    private static final String CREDENTIAL_IDS =  "credentialIDs";
    private static final String SERIALIZING_ERROR = "Error serializing request body to JSON";
    private static final String INFO_PATH = "/csc/v2/credentials/info";
    private static final String LIST_PATH  = "/csc/v2/credentials/list";


    @Override
    public Mono<Boolean> validateCredentials() {
        SigningRequest signatureRequest = SigningRequest.builder().build();
        return qtspAuthClient.requestAccessToken(signatureRequest, SIGNATURE_REMOTE_SCOPE_SERVICE)
                .flatMap(this::validateCertificate);
    }

    @Override
    public Mono<String> requestCertificateInfo(String accessToken, String credentialID) {
        String credentialsInfoEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + INFO_PATH;
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put(CREDENTIAL_ID, credentialID);
        requestBody.put(CERTIFICATES, "chain");
        requestBody.put(CERT_INFO, "true");
        requestBody.put(AUTH_INFO, "true");

        String requestBodySignature;
        try {
            requestBodySignature = objectMapper.writeValueAsString(requestBody);
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException(SERIALIZING_ERROR, e));
        }
        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));
        return httpUtils.postRequest(credentialsInfoEndpoint, headers, requestBodySignature)
                .doOnError(error -> log.error("Error sending credential to sign: {}", error.getMessage()));
    }

    @Override
    public Mono<DetailedIssuer> extractIssuerFromCertificateInfo(String certificateInfo) {
        try {
            log.info("Starting extraction of issuer from certificate info");
            JsonNode certificateInfoNode = objectMapper.readTree(certificateInfo);
            String subjectDN = certificateInfoNode.get("cert").get("subjectDN").asText();
            String serialNumber = certificateInfoNode.get("cert").get("serialNumber").asText();
            LdapName ldapDN = new LdapName(subjectDN);
            Map<String, String> dnAttributes = new HashMap<>();

            for (Rdn rdn : ldapDN.getRdns()) {
                dnAttributes.put(rdn.getType(), rdn.getValue().toString());
            }
            JsonNode certificatesArray = certificateInfoNode.get("cert").get(CERTIFICATES);

            Mono<String> organizationIdentifierMono = (certificatesArray != null && certificatesArray.isArray())
                    ? Flux.fromIterable(certificatesArray)
                    .concatMap(certNode -> {
                        String base64Cert = certNode.asText();
                        byte[] decodedBytes = Base64.getDecoder().decode(base64Cert);
                        String decodedCert = new String(decodedBytes, StandardCharsets.UTF_8);
                        Pattern pattern = Pattern.compile("organizationIdentifier\\s*=\\s*([\\w\\-]+)");
                        Matcher matcher = pattern.matcher(decodedCert);
                        if (matcher.find()) {
                            return Mono.just(matcher.group(1));
                        } else {
                            return extractOrgFromX509(decodedBytes);
                        }
                    })
                    .next()
                    : Mono.empty();

            return organizationIdentifierMono
                    .switchIfEmpty(Mono.error(new OrganizationIdentifierNotFoundException("organizationIdentifier not found in the certificate.")))
                    .flatMap(orgId -> {
                        if (orgId == null || orgId.isEmpty()) {
                            return Mono.error(new OrganizationIdentifierNotFoundException("organizationIdentifier not found in the certificate."));
                        }
                        DetailedIssuer detailedIssuer = DetailedIssuer.builder()
                                .id(DID_ELSI + orgId)
                                .organizationIdentifier(orgId)
                                .organization(dnAttributes.get("O"))
                                .country(dnAttributes.get("C"))
                                .commonName(dnAttributes.get("CN"))
                                .serialNumber(serialNumber)
                                .build();
                        return Mono.just(detailedIssuer);
                    });
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException("Error parsing certificate info", e));
        } catch (InvalidNameException e) {
            return Mono.error(new RuntimeException("Error parsing subjectDN", e));
        } catch (Exception e) {
            return Mono.error(new RuntimeException("Unexpected error", e));
        }
    }

    @Override
    public boolean isServerMode() {
        return SIGNATURE_REMOTE_TYPE_SERVER.equals(remoteSignatureConfig.getRemoteSignatureType());
    }

    @Override
    public Mono<DetailedIssuer> resolveRemoteDetailedIssuer() {
        return validateCredentials()
                .flatMap(valid -> {
                    if (Boolean.FALSE.equals(valid)) {
                        return Mono.error(new RemoteSignatureException("Credentials mismatch."));
                    }

                    return qtspAuthClient.requestAccessToken(null, SIGNATURE_REMOTE_SCOPE_SERVICE)
                            .flatMap(token -> requestCertificateInfo(token, remoteSignatureConfig.getRemoteSignatureCredentialId()))
                            .flatMap(this::extractIssuerFromCertificateInfo);

                });
    }

    @Override
    public String getCredentialId() {
        return remoteSignatureConfig.getRemoteSignatureCredentialId();
    }

    @Override
    public Mono<List<String>> extractX5cChain(String certificateInfoJson) {
        return Mono.fromCallable(() -> {
            JsonNode root = objectMapper.readTree(certificateInfoJson);
            JsonNode certNode = root.path("cert");
            JsonNode chain = certNode.path("certificates");
            if (!chain.isArray()) {
                return List.of();
            }
            List<String> x5c = new ArrayList<>();
            for (JsonNode n : chain) {
                if (n != null && n.isTextual()) {
                    x5c.add(n.asText());
                }
            }
            return x5c;
        });
    }

    private Mono<Boolean> validateCertificate(String accessToken) {
        String credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        String credentialListEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + LIST_PATH;

        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put(CREDENTIAL_INFO, true);
        requestBody.put(CERTIFICATES, "chain");
        requestBody.put(CERT_INFO, true);
        requestBody.put(AUTH_INFO, true);
        requestBody.put(ONLY_VALID, true);
        requestBody.put(LANG, 0);
        requestBody.put(CLIENT_DATA, "string");
        try {
            String requestBodyJson = objectMapper.writeValueAsString(requestBody);
            return httpUtils.postRequest(credentialListEndpoint, headers, requestBodyJson)
                    .flatMap(responseJson -> {
                        try {
                            Map<String, List<String>> responseMap = objectMapper.readValue(responseJson, Map.class);
                            List<String> receivedCredentialIDs = responseMap.get(CREDENTIAL_IDS);
                            boolean isValid = receivedCredentialIDs != null &&
                                    receivedCredentialIDs.stream()
                                            .anyMatch(id -> id.trim().equalsIgnoreCase(credentialID.trim()));
                            return Mono.just(isValid);
                        } catch (JsonProcessingException e) {
                            return Mono.error(new RemoteSignatureException("Error parsing certificate list response", e));
                        }
                    })
                    .switchIfEmpty(Mono.just(false))
                    .doOnError(error -> log.error("Error validating certificate: {}", error.getMessage()));
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException(SERIALIZING_ERROR, e));
        }
    }

    private Mono<String> extractOrgFromX509(byte[] decodedBytes) {
        return Mono.defer(() -> {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedBytes));
                String certAsString = x509Certificate.toString();
                Pattern certPattern = Pattern.compile("OID\\.2\\.5\\.4\\.97=([^,\\s]+)");
                Matcher certMatcher = certPattern.matcher(certAsString);
                if (certMatcher.find()) {
                    String orgId = certMatcher.group(1);
                    return Mono.just(orgId);
                } else {
                    return Mono.empty();
                }
            } catch (Exception e) {
                log.debug("Error parsing certificate: {}", e.getMessage());
                return Mono.empty();
            }
        });
    }

}
