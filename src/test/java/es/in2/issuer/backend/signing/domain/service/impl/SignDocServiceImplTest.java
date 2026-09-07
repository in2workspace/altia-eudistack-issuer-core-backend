package es.in2.issuer.backend.signing.domain.service.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.signing.domain.exception.SignatureProcessingException;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import es.in2.issuer.backend.signing.domain.util.JwtUtils;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SignDocServiceImplTest {

    @Mock
    private CscPort cscPort;

    // Real implementation, not mocked -- H1's fix is exercised end to end against genuine
    // cryptographic material, not against a literal placeholder string.
    private final JwtUtils jwtUtils = new JwtUtils();

    private SignDocServiceImpl signDocService;

    private static final String SIGN_ALGO_OID = "OID_sign_algorithm";

    private static KeyPair leafKeyPair;
    private static X509Certificate leafCert;
    private static KeyPair otherKeyPair;
    private static X509Certificate otherCert;

    @BeforeAll
    static void generateTestCertificates() throws Exception {
        leafKeyPair = generateEcKeyPair();
        leafCert = selfSignedCertificate(leafKeyPair, "CN=Test QTSP Certificate");
        otherKeyPair = generateEcKeyPair();
        otherCert = selfSignedCertificate(otherKeyPair, "CN=A Different Certificate");
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate selfSignedCertificate(KeyPair keyPair, String dn) throws Exception {
        long now = System.currentTimeMillis();
        X500Name subject = new X500Name(dn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now),
                new Date(now - 60_000L),
                new Date(now + 3_600_000L),
                subject,
                keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(builder.build(signer));
    }

    /** Builds a real, compact-serialized JWS -- the exact shape {@code cscPort.signDoc} returns. */
    private static String signedJws(String payloadJson, JWSAlgorithm alg, Object signingKey, X509Certificate x5cCert)
            throws Exception {
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(alg);
        if (x5cCert != null) {
            headerBuilder.x509CertChain(List.of(Base64.encode(x5cCert.getEncoded())));
        }
        SignedJWT jwt = new SignedJWT(headerBuilder.build(), JWTClaimsSet.parse(payloadJson));
        if (signingKey instanceof ECPrivateKey ecKey) {
            jwt.sign(new ECDSASigner(ecKey));
        } else {
            jwt.sign(new MACSigner((byte[]) signingKey));
        }
        return jwt.serialize();
    }

    private static RemoteSignatureDto cfg() {
        return new RemoteSignatureDto(
                "provider",
                "1",
                "https://api.external.com",
                "https://api.external.com",
                "sign-doc",
                "cred-123", "pwd",
                "PT10M",
                "clientId", "clientSecret",
                "",
                "",
                "",
                "",
                ""
        );
    }

    private static SigningRequest request(SigningType type, String data) {
        SigningContext context = new SigningContext("token", "proc", "email");
        return SigningRequest.builder()
                .type(type)
                .data(data)
                .context(context)
                .remoteSignature(cfg())
                .build();
    }

    private static CertificateInfo certInfoFor(X509Certificate cert) throws Exception {
        return new CertificateInfo(
                List.of(Base64.encode(cert.getEncoded()).toString()),
                null, null, null, null, null,
                List.of(SIGN_ALGO_OID), null, false);
    }

    private void stubSigningChain(RemoteSignatureDto cfg, SigningRequest req, CertificateInfo certInfo, String signedJwt) {
        String signedB64 = Base64.encode(signedJwt).toString();
        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, true, req.data()))
                .thenReturn(Mono.just("access-token"));
        when(cscPort.getCredentialInfo(cfg, "access-token", cfg.credentialId()))
                .thenReturn(Mono.just(certInfo));
        when(cscPort.authorizeForDoc(cfg, "access-token"))
                .thenReturn(Mono.just("sad-123"));
        when(cscPort.signDoc(eq(cfg), eq("access-token"), eq("sad-123"), anyString(), eq(SIGN_ALGO_OID)))
                .thenReturn(Mono.just(signedB64));
    }

    @Test
    void signIssuedCredential_success() throws Exception {
        signDocService = new SignDocServiceImpl(cscPort, jwtUtils);
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        CertificateInfo certInfo = certInfoFor(leafCert);
        String signedJwt = signedJws("{\"vc\":1}", JWSAlgorithm.ES256, leafKeyPair.getPrivate(), leafCert);
        stubSigningChain(req.remoteSignature(), req, certInfo, signedJwt);

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .assertNext(result -> {
                    assertThat(result.type()).isEqualTo(SigningType.JADES);
                    assertThat(result.data()).isEqualTo(signedJwt);
                })
                .verifyComplete();
    }

    @Test
    void signSystemCredential_success() throws Exception {
        signDocService = new SignDocServiceImpl(cscPort, jwtUtils);
        SigningRequest req = request(SigningType.COSE, "{\"a\":1}");
        CertificateInfo certInfo = certInfoFor(leafCert);
        String signedJwt = signedJws("{\"a\":1}", JWSAlgorithm.ES256, leafKeyPair.getPrivate(), leafCert);
        stubSigningChain(req.remoteSignature(), req, certInfo, signedJwt);

        StepVerifier.create(signDocService.signSystemCredential(req))
                .assertNext(result -> {
                    assertThat(result.type()).isEqualTo(SigningType.COSE);
                    assertThat(result.data()).isEqualTo(signedJwt);
                })
                .verifyComplete();
    }

    @Test
    void signIssuedCredential_failsWhenPayloadMismatch() throws Exception {
        signDocService = new SignDocServiceImpl(cscPort, jwtUtils);
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        CertificateInfo certInfo = certInfoFor(leafCert);
        // Signed for a *different* payload than what was requested.
        String signedJwt = signedJws("{\"vc\":999}", JWSAlgorithm.ES256, leafKeyPair.getPrivate(), leafCert);
        stubSigningChain(req.remoteSignature(), req, certInfo, signedJwt);

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(SignatureProcessingException.class);
                    assertThat(ex.getMessage()).contains("does not match");
                })
                .verify();
    }

    @Test
    void signIssuedCredential_failsWhenAlgorithmNotAllowed() throws Exception {
        signDocService = new SignDocServiceImpl(cscPort, jwtUtils);
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        CertificateInfo certInfo = certInfoFor(leafCert);
        byte[] hmacSecret = new byte[32];
        String signedJwt = signedJws("{\"vc\":1}", JWSAlgorithm.HS256, hmacSecret, null);
        stubSigningChain(req.remoteSignature(), req, certInfo, signedJwt);

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(SignatureProcessingException.class);
                    assertThat(ex.getMessage()).contains("disallowed algorithm");
                })
                .verify();
    }

    @Test
    void signIssuedCredential_failsWhenX5cMissing() throws Exception {
        signDocService = new SignDocServiceImpl(cscPort, jwtUtils);
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        CertificateInfo certInfo = certInfoFor(leafCert);
        String signedJwt = signedJws("{\"vc\":1}", JWSAlgorithm.ES256, leafKeyPair.getPrivate(), null);
        stubSigningChain(req.remoteSignature(), req, certInfo, signedJwt);

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(SignatureProcessingException.class);
                    assertThat(ex.getMessage()).contains("missing its certificate chain");
                })
                .verify();
    }

    @Test
    void signIssuedCredential_failsWhenCertificateDoesNotMatchCredentialInfo() throws Exception {
        signDocService = new SignDocServiceImpl(cscPort, jwtUtils);
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        // certInfo says the credential's certificate is `otherCert`, but the JWS carries `leafCert`.
        CertificateInfo certInfo = certInfoFor(otherCert);
        String signedJwt = signedJws("{\"vc\":1}", JWSAlgorithm.ES256, leafKeyPair.getPrivate(), leafCert);
        stubSigningChain(req.remoteSignature(), req, certInfo, signedJwt);

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(SignatureProcessingException.class);
                    assertThat(ex.getMessage()).contains("does not match the credential's own certificate");
                })
                .verify();
    }

    @Test
    void signIssuedCredential_failsWhenSignatureDoesNotVerify() throws Exception {
        signDocService = new SignDocServiceImpl(cscPort, jwtUtils);
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        CertificateInfo certInfo = certInfoFor(leafCert);
        // Signed with a DIFFERENT private key than the one behind the x5c leaf certificate --
        // the payload and certInfo both look legitimate, only the signature itself is forged.
        String signedJwt = signedJws("{\"vc\":1}", JWSAlgorithm.ES256, otherKeyPair.getPrivate(), leafCert);
        stubSigningChain(req.remoteSignature(), req, certInfo, signedJwt);

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .expectErrorSatisfies(ex -> {
                    assertThat(ex).isInstanceOf(SignatureProcessingException.class);
                    assertThat(ex.getMessage()).contains("Signature verification failed");
                })
                .verify();
    }

    @Test
    void signIssuedCredential_retries_thenSucceeds() throws Exception {
        signDocService = new SignDocServiceImpl(cscPort, jwtUtils);
        SigningRequest req = request(SigningType.JADES, "{\"vc\":1}");
        RemoteSignatureDto cfg = req.remoteSignature();
        CertificateInfo certInfo = certInfoFor(leafCert);
        String signedJwt = signedJws("{\"vc\":1}", JWSAlgorithm.ES256, leafKeyPair.getPrivate(), leafCert);
        String signedB64 = Base64.encode(signedJwt).toString();

        WebClientResponseException serverError = WebClientResponseException.create(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                HttpHeaders.EMPTY,
                null,
                null
        );

        when(cscPort.requestAccessToken(cfg, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, true, req.data()))
                .thenReturn(Mono.just("access-token"));
        when(cscPort.getCredentialInfo(cfg, "access-token", cfg.credentialId()))
                .thenReturn(Mono.just(certInfo));
        when(cscPort.authorizeForDoc(cfg, "access-token"))
                .thenReturn(Mono.just("sad-123"));
        when(cscPort.signDoc(eq(cfg), eq("access-token"), eq("sad-123"), anyString(), eq(SIGN_ALGO_OID)))
                .thenReturn(Mono.error(serverError))
                .thenReturn(Mono.error(serverError))
                .thenReturn(Mono.just(signedB64));

        StepVerifier.create(signDocService.signIssuedCredential(req, "proc"))
                .assertNext(result -> assertThat(result.data()).isEqualTo(signedJwt))
                .verifyComplete();

        verify(cscPort, times(3)).signDoc(any(), anyString(), anyString(), anyString(), anyString());
    }
}
