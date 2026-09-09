package es.in2.issuer.backend.signing.domain.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.signing.domain.exception.SignatureProcessingException;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.service.SignDocService;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.domain.util.JwtUtils;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;

@Slf4j
@Service
@RequiredArgsConstructor
public class SignDocServiceImpl implements SignDocService {

    // Mirrors JadesHeaderBuilderServiceImpl.mapOidToJwtAlg's output set -- anything else (including
    // "none" or an HMAC alg) is rejected regardless of whether some verifier would happen to accept
    // it, closing the classic algorithm-confusion class of attack.
    private static final Set<JWSAlgorithm> ALLOWED_ALGORITHMS = Set.of(
            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.PS256
    );

    private final CscPort cscPort;
    private final JwtUtils jwtUtils;

    @Override
    public Mono<SigningResult> signIssuedCredential(SigningRequest signingRequest, String issuanceId) {
        log.debug("SignDocServiceImpl - signIssuedCredential, issuanceId: {}", issuanceId);
        return signWithRetry(signingRequest, "signIssuedCredential")
                .doOnSuccess(_ -> log.info("Successfully signed credential for issuanceId: {}", issuanceId));
    }

    @Override
    public Mono<SigningResult> signSystemCredential(SigningRequest signingRequest) {
        log.debug("SignDocServiceImpl - signSystemCredential");
        return signWithRetry(signingRequest, "signSystemCredential");
    }

    private Mono<SigningResult> signWithRetry(SigningRequest request, String operationName) {
        return Mono.defer(() -> executeSigningFlow(request))
                .doOnSuccess(result -> log.info("Remote signing succeeded ({}). resultLength={}", operationName,
                        result != null && result.data() != null ? result.data().length() : 0))
                .retryWhen(
                        Retry.backoff(3, Duration.ofSeconds(1))
                                .maxBackoff(Duration.ofSeconds(5))
                                .jitter(0.5)
                                .filter(QtspRetryPolicy::isRecoverable)
                                .doBeforeRetry(rs -> log.warn("Retrying remote signing ({}). attempt={} of 3, reason={}",
                                        operationName, rs.totalRetries() + 1,
                                        rs.failure() != null ? rs.failure().getMessage() : "n/a"))
                )
                .doOnError(ex -> log.error("Remote signing failed after retries ({}). reason={}", operationName, ex.getMessage(), ex));
    }

    private Mono<SigningResult> executeSigningFlow(SigningRequest request) {
        RemoteSignatureDto cfg = request.remoteSignature();
        String docB64 = Base64.getEncoder().encodeToString(request.data().getBytes(StandardCharsets.UTF_8));

        return cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, true, request.data())
                .flatMap(accessToken -> cscPort.getCredentialInfo(cfg, accessToken, cfg.credentialId())
                        .flatMap(certInfo -> {
                            String signAlgoOid = certInfo.keyAlgorithms().getFirst();
                            return cscPort.authorizeForDoc(cfg, accessToken)
                                    .flatMap(sad -> cscPort.signDoc(cfg, accessToken, sad, docB64, signAlgoOid))
                                    .flatMap(signedDocB64 -> verifyAndBuild(request, certInfo, signedDocB64));
                        })
                );
    }

    private Mono<SigningResult> verifyAndBuild(SigningRequest request, CertificateInfo certInfo, String signedDocB64) {
        return Mono.fromCallable(() -> {
            String signedDoc = new String(Base64.getDecoder().decode(signedDocB64), StandardCharsets.UTF_8);
            String receivedPayload = jwtUtils.decodePayload(signedDoc);
            if (!jwtUtils.areJsonsEqual(receivedPayload, request.data())) {
                throw new SignatureProcessingException("Signed payload received does not match the original data");
            }
            verifySignature(signedDoc, certInfo);
            return new SigningResult(request.type(), signedDoc);
        });
    }

    private void verifySignature(String signedDoc, CertificateInfo certInfo) {
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(signedDoc);
        } catch (ParseException _) {
            throw new SignatureProcessingException("Signed document is not a well-formed JWS");
        }

        JWSHeader header = signedJWT.getHeader();
        if (!ALLOWED_ALGORITHMS.contains(header.getAlgorithm())) {
            throw new SignatureProcessingException("Signed document uses a disallowed algorithm");
        }

        List<com.nimbusds.jose.util.Base64> x5c = header.getX509CertChain();
        if (x5c == null || x5c.isEmpty()) {
            throw new SignatureProcessingException("Signed document is missing its certificate chain (x5c)");
        }

        X509Certificate leaf = X509CertUtils.parse(x5c.getFirst().decode());
        if (leaf == null) {
            throw new SignatureProcessingException("Could not parse the leaf certificate from x5c");
        }

        List<String> expectedCertificates = certInfo.certificates();
        String expectedLeafBase64 = (expectedCertificates == null || expectedCertificates.isEmpty())
                ? null : expectedCertificates.getFirst();

        X509Certificate expectedLeaf;
        try {
            expectedLeaf = expectedLeafBase64 == null
                    ? null : X509CertUtils.parse(Base64.getDecoder().decode(expectedLeafBase64));
        } catch (IllegalArgumentException ex) {
            // W2 (code-review): certInfo.certificates() comes back from the QTSP (getCredentialInfo),
            // not from the signed document itself -- invalid Base64 there is a malformed response, not
            // a well-formed rejection, but it must still surface as SignatureProcessingException rather
            // than an unmapped 500 (H1's closed error contract).
            throw new SignatureProcessingException(
                    "Could not parse the credential's own certificate", ex);
        }

        if (expectedLeaf == null || !leaf.equals(expectedLeaf)) {
            throw new SignatureProcessingException(
                    "Signed document's certificate does not match the credential's own certificate");
        }

        try {
            JWSVerifier verifier = buildVerifier(header.getAlgorithm(), leaf);
            if (!signedJWT.verify(verifier)) {
                throw new SignatureProcessingException(
                        "Signature verification failed against the certificate in x5c");
            }
        } catch (JOSEException _) {
            throw new SignatureProcessingException(
                    "Error verifying the signed document's signature");
        } catch (ClassCastException | IllegalArgumentException ex) {
            // W2 (code-review): the leaf's actual key type can disagree with the JWS alg family
            // (e.g. an RSA leaf under an ES256 header), which JWSAlgorithm.Family.contains does not
            // rule out -- the cast in buildVerifier then throws ClassCastException, and the verifier
            // constructors themselves throw IllegalArgumentException on a malformed key. Neither is a
            // JOSEException, so both must be mapped here too or this leg breaks H1's closed error
            // contract (a 500 instead of SignatureProcessingException) for what is still a rejection,
            // never a bypass.
            throw new SignatureProcessingException(
                    "Error verifying the signed document's signature", ex);
        }
    }

    private JWSVerifier buildVerifier(JWSAlgorithm alg, X509Certificate leaf) throws JOSEException {
        if (JWSAlgorithm.Family.EC.contains(alg)) {
            return new ECDSAVerifier((ECPublicKey) leaf.getPublicKey());
        }
        if (JWSAlgorithm.Family.RSA.contains(alg)) {
            return new RSASSAVerifier((RSAPublicKey) leaf.getPublicKey());
        }
        throw new JOSEException("Unsupported algorithm family: " + alg);
    }
}
