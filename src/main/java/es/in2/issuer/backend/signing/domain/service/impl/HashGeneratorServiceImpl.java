package es.in2.issuer.backend.signing.domain.service.impl;
import es.in2.issuer.backend.signing.domain.exception.HashGenerationException;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
public class HashGeneratorServiceImpl implements  HashGeneratorService {

    @Override
    public String generateHash(String unsignedDocument, String algorithm) throws HashGenerationException {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new HashGenerationException("Algorithm is required");
        }

        if ("2.16.840.1.101.3.4.2.1".equals(algorithm)) {
            return generateSHA256(unsignedDocument);
        } else {
            throw new HashGenerationException("Error generating hash: algorithm not supported");
            }
    }
    @Override
    public String generateSHA256(String unsignedDocument) throws HashGenerationException {
        if (unsignedDocument == null || unsignedDocument.isEmpty()) {
            throw new HashGenerationException("The document cannot be null or empty");
        }
        byte[] hashBytes = sha256Digest(unsignedDocument.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    @Override
    public byte[] sha256Digest(byte[] input) throws HashGenerationException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new HashGenerationException("SHA-256 algorithm not supported", e);
        }
    }
}
