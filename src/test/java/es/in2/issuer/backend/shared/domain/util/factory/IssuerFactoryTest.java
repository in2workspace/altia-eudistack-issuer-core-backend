package es.in2.issuer.backend.shared.domain.util.factory;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.service.impl.SigningRecoveryServiceImpl;
import es.in2.issuer.backend.signing.domain.service.impl.QtspIssuerServiceImpl;
import es.in2.issuer.backend.signing.infrastructure.config.DefaultSignerConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.TimeoutException;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.DID_ELSI;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuerFactoryTest {

    @Mock private DefaultSignerConfig defaultSignerConfig;
    @Mock private SigningRecoveryServiceImpl signingRecoveryServiceImpl;
    @Mock private QtspIssuerServiceImpl qtspIssuerServiceImpl;

    @InjectMocks private IssuerFactory issuerFactory;

    private final String procedureId = "proc-123";

    @Test
    void createDetailedIssuer_LocalServerSide_ReturnsFromDefaultConfig() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(true);

        when(defaultSignerConfig.getOrganizationIdentifier()).thenReturn("ORG-ID");
        when(defaultSignerConfig.getOrganization()).thenReturn("MyOrg");
        when(defaultSignerConfig.getCountry()).thenReturn("ES");
        when(defaultSignerConfig.getCommonName()).thenReturn("CN");
        when(defaultSignerConfig.getSerialNumber()).thenReturn("SN123");

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .assertNext(issuer -> {
                    assertEquals(DID_ELSI + "ORG-ID", issuer.getId());
                    assertEquals("ORG-ID", issuer.organizationIdentifier());
                    assertEquals("MyOrg", issuer.organization());
                    assertEquals("ES", issuer.country());
                    assertEquals("CN", issuer.commonName());
                    assertEquals("SN123", issuer.serialNumber());
                })
                .verifyComplete();

        verify(qtspIssuerServiceImpl).isServerMode();
        verifyNoMoreInteractions(qtspIssuerServiceImpl);
        verifyNoInteractions(signingRecoveryServiceImpl);
    }

    @Test
    void createSimpleIssuer_LocalServerSide_ReturnsFromDefaultConfig() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(true);
        when(defaultSignerConfig.getOrganizationIdentifier()).thenReturn("ORG-ID");

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> assertEquals(DID_ELSI + "ORG-ID", simple.getId()))
                .verifyComplete();

        verify(qtspIssuerServiceImpl).isServerMode();
        verifyNoMoreInteractions(qtspIssuerServiceImpl);
        verifyNoInteractions(signingRecoveryServiceImpl);
    }

    @Test
    void createDetailedIssuer_Remote_SuccessPath() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(false);

        DetailedIssuer expected = DetailedIssuer.builder()
                .id("id1")
                .organizationIdentifier("org1")
                .organization("o")
                .country("ES")
                .commonName("CN")
                .serialNumber("SN")
                .build();

        when(qtspIssuerServiceImpl.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.just(expected));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectNext(expected)
                .verifyComplete();

        verify(qtspIssuerServiceImpl).isServerMode();
        verify(qtspIssuerServiceImpl).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerServiceImpl);
        verifyNoInteractions(signingRecoveryServiceImpl);
    }

    @Test
    void createSimpleIssuer_Remote_SuccessPath() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(false);

        DetailedIssuer detailed = DetailedIssuer.builder()
                .id("issuer-id")
                .build();

        when(qtspIssuerServiceImpl.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.just(detailed));

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> assertEquals("issuer-id", simple.getId()))
                .verifyComplete();

        verify(qtspIssuerServiceImpl).isServerMode();
        verify(qtspIssuerServiceImpl).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerServiceImpl);
        verifyNoInteractions(signingRecoveryServiceImpl);
    }

    @Test
    void createDetailedIssuer_Remote_Error_PropagatesError() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(false);

        RemoteSignatureException ex = new RemoteSignatureException("boom");
        when(qtspIssuerServiceImpl.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(ex));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectErrorSatisfies(err -> assertEquals(ex, err))
                .verify();

        verify(qtspIssuerServiceImpl).isServerMode();
        verify(qtspIssuerServiceImpl).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerServiceImpl);
        verifyNoInteractions(signingRecoveryServiceImpl);
    }

    @Test
    void createDetailedIssuerAndNotifyOnError_Remote_Error_CompletesEmptyAndCallsPostRecover() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(false);

        when(qtspIssuerServiceImpl.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new RemoteSignatureException("credentials mismatch")));

        when(signingRecoveryServiceImpl.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .verifyComplete();

        verify(qtspIssuerServiceImpl).isServerMode();
        verify(qtspIssuerServiceImpl).resolveRemoteDetailedIssuer();
        verify(signingRecoveryServiceImpl).handlePostRecoverError(procedureId, "");
        verifyNoMoreInteractions(qtspIssuerServiceImpl, signingRecoveryServiceImpl);
    }

    @Test
    void createDetailedIssuerAndNotifyOnError_Remote_PostRecoverFails_PropagatesPostRecoverError() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(false);

        when(qtspIssuerServiceImpl.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new RemoteSignatureException("boom")));

        RuntimeException postEx = new RuntimeException("post-recover failed");
        when(signingRecoveryServiceImpl.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.error(postEx));

        StepVerifier.create(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .expectErrorSatisfies(err -> assertEquals(postEx, err))
                .verify();

        verify(qtspIssuerServiceImpl).isServerMode();
        verify(qtspIssuerServiceImpl).resolveRemoteDetailedIssuer();
        verify(signingRecoveryServiceImpl).handlePostRecoverError(procedureId, "");
        verifyNoMoreInteractions(qtspIssuerServiceImpl, signingRecoveryServiceImpl);
    }

    @Test
    void createDetailedIssuer_Remote_RecoverableErrors_ThenRetryExhausted() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(false);

        when(qtspIssuerServiceImpl.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new TimeoutException("t1")))
                .thenReturn(Mono.error(new TimeoutException("t2")))
                .thenReturn(Mono.error(new TimeoutException("t3")))
                .thenReturn(Mono.error(new TimeoutException("t4")));

        StepVerifier.create(issuerFactory.createDetailedIssuer())
                .expectErrorSatisfies(err -> {
                    assertEquals("reactor.core.Exceptions$RetryExhaustedException", err.getClass().getName());
                    assertEquals(TimeoutException.class, err.getCause().getClass());
                })
                .verify();

        verify(qtspIssuerServiceImpl).isServerMode();
        verify(qtspIssuerServiceImpl, times(1)).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerServiceImpl);
        verifyNoInteractions(signingRecoveryServiceImpl);
    }


    @Test
    void createDetailedIssuerAndNotifyOnError_Remote_RecoverableErrors_ThenPostRecoverCompletesEmpty() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(false);

        when(qtspIssuerServiceImpl.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new TimeoutException("t1")));

        when(signingRecoveryServiceImpl.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createDetailedIssuerAndNotifyOnError(procedureId, ""))
                .verifyComplete();

        verify(qtspIssuerServiceImpl).isServerMode();
        verify(qtspIssuerServiceImpl, times(1)).resolveRemoteDetailedIssuer();
        verify(signingRecoveryServiceImpl).handlePostRecoverError(procedureId, "");
        verifyNoMoreInteractions(qtspIssuerServiceImpl, signingRecoveryServiceImpl);
    }

    @Test
    void createSimpleIssuerAndNotifyOnError_Remote_Error_CompletesEmptyAndCallsPostRecover() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(false);

        when(qtspIssuerServiceImpl.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.error(new RemoteSignatureException("boom")));

        when(signingRecoveryServiceImpl.handlePostRecoverError(procedureId, ""))
                .thenReturn(Mono.empty());

        StepVerifier.create(issuerFactory.createSimpleIssuerAndNotifyOnError(procedureId, ""))
                .verifyComplete();

        verify(qtspIssuerServiceImpl).isServerMode();
        verify(qtspIssuerServiceImpl).resolveRemoteDetailedIssuer();
        verify(signingRecoveryServiceImpl).handlePostRecoverError(procedureId, "");
        verifyNoMoreInteractions(qtspIssuerServiceImpl, signingRecoveryServiceImpl);
    }

    @Test
    void createSimpleIssuer_Remote_Success_MapsToSimpleIssuer() {
        when(qtspIssuerServiceImpl.isServerMode()).thenReturn(false);

        DetailedIssuer detailed = DetailedIssuer.builder()
                .id("did:elsi:ABC")
                .build();

        when(qtspIssuerServiceImpl.resolveRemoteDetailedIssuer())
                .thenReturn(Mono.just(detailed));

        StepVerifier.create(issuerFactory.createSimpleIssuer())
                .assertNext(simple -> {
                    assertEquals("did:elsi:ABC", simple.getId());
                })
                .verifyComplete();

        verify(qtspIssuerServiceImpl).isServerMode();
        verify(qtspIssuerServiceImpl).resolveRemoteDetailedIssuer();
        verifyNoMoreInteractions(qtspIssuerServiceImpl);
        verifyNoInteractions(signingRecoveryServiceImpl);
    }
}
