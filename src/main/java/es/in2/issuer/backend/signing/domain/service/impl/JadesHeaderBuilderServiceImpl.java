package es.in2.issuer.backend.signing.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JadesHeaderBuilderServiceImpl implements JadesHeaderBuilderService {

    private final ObjectMapper objectMapper;

    @Override
    public String buildHeader(CertificateInfo certInfo, JadesProfile profile) {
        try {
            Map<String, Object> header = new HashMap<>();

            String jwtAlg = mapOidToJwtAlg(certInfo.keyAlgorithms());

            header.put("alg", jwtAlg);
            header.put("typ", "JWT");

            header.put("x5c", certInfo.certificates());

            if (profile == JadesProfile.JADES_B_T) {
                header.put("sigT", Instant.now().toString());
            }
            return objectMapper.writeValueAsString(header);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to build JAdES header", e);
        }
    }

    private String mapOidToJwtAlg(java.util.List<String> oids) {
        if (oids == null || oids.isEmpty()) {
            throw new IllegalArgumentException("No signing algorithm found in certificate info");
        }

        String oid = oids.get(0);

        return switch (oid) {
            case "1.2.840.10045.4.3.2" -> "ES256";
            case "1.2.840.10045.4.3.3" -> "ES384";
            case "1.2.840.10045.4.3.4" -> "ES512";
            default -> throw new IllegalArgumentException("Unsupported OID: " + oid);
        };
    }
}
