package es.in2.issuer.backend.signing.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JadesHeaderBuilderServiceImpl implements JadesHeaderBuilderService {

    private final ObjectMapper objectMapper;

    @Override
    public String buildHeader(CertificateInfo certInfo, JadesProfile profile) {
        try {
            if (certInfo == null) throw new IllegalArgumentException("certInfo is required");
            if (profile == null) throw new IllegalArgumentException("profile is required");

            Map<String, Object> header = new HashMap<>();

            String jwtAlg = mapOidToJwtAlg(certInfo.keyAlgorithms());
            header.put("alg", jwtAlg);

            header.put("typ", "JWT");

            header.put("x5c", certInfo.certificates());

            applyProfileSpecificFields(header, profile);

            return objectMapper.writeValueAsString(header);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build JAdES header", e);
        }
    }

    private void applyProfileSpecificFields(Map<String, Object> header, JadesProfile profile) {
        switch (profile) {
            case JADES_B_B -> {
            }
            case JADES_B_T -> {
                header.put("sigT", Instant.now().toString());
            }
            case JADES_B_LT, JADES_B_LTA -> {
                throw new IllegalStateException(profile + " not yet supported");
            }
        }
    }

    private String mapOidToJwtAlg(List<String> oids) {
        if (oids == null || oids.isEmpty()) {
            throw new IllegalArgumentException("No signing algorithm found in certificate info");
        }

        return switch (oids.get(0)) {
            case "1.2.840.10045.4.3.2" -> "ES256";
            case "1.2.840.10045.4.3.3" -> "ES384";
            case "1.2.840.10045.4.3.4" -> "ES512";
            default -> throw new IllegalArgumentException("Unsupported OID: " + oids.get(0));
        };
    }
}