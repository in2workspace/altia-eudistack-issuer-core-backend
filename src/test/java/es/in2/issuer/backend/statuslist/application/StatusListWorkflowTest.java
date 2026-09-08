package es.in2.issuer.backend.statuslist.application;


import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StatusListWorkflowTest {

    @Mock
    private StatusListProvider statusListProvider;

    private StatusListWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new StatusListWorkflow(statusListProvider);
    }

    @Test
    void allocateEntry_whenSuccess_returnsEntryAndCallsProvider() {
        StatusPurpose purpose = mock(StatusPurpose.class);
        StatusListFormat format = StatusListFormat.BITSTRING_VC;
        String issuanceId = "proc-123";
        String token = "token-abc";

        StatusListEntry entry = mock(StatusListEntry.class);
        when(entry.statusListCredential()).thenReturn("https://issuer.example/status-list/55");
        when(entry.statusListIndex()).thenReturn("7");

        when(statusListProvider.allocateEntry(purpose, format, issuanceId, token, "https://issuer.example.com"))
                .thenReturn(Mono.just(entry));

        StepVerifier.create(workflow.allocateEntry(purpose, format, issuanceId, token, "https://issuer.example.com"))
                .expectNext(entry)
                .verifyComplete();

        verify(statusListProvider).allocateEntry(purpose, format, issuanceId, token, "https://issuer.example.com");
        verifyNoMoreInteractions(statusListProvider);
    }


    @Test
    void allocateEntry_whenProviderErrors_propagatesErrorAndCallsProvider() {
        StatusPurpose purpose = mock(StatusPurpose.class);
        StatusListFormat format = StatusListFormat.BITSTRING_VC;
        String issuanceId = "proc-123";
        String token = "token-abc";

        RuntimeException ex = new RuntimeException("boom");

        when(statusListProvider.allocateEntry(purpose, format, issuanceId, token, "https://issuer.example.com"))
                .thenReturn(Mono.error(ex));

        StepVerifier.create(workflow.allocateEntry(purpose, format, issuanceId, token, "https://issuer.example.com"))
                .expectErrorMatches(e -> e instanceof RuntimeException && "boom".equals(e.getMessage()))
                .verify();

        verify(statusListProvider).allocateEntry(purpose, format, issuanceId, token, "https://issuer.example.com");
        verifyNoMoreInteractions(statusListProvider);
    }

    @Test
    void allocateEntry_whenPurposeIsNull_throwsAndDoesNotCallProvider() {
        StatusListFormat format = StatusListFormat.BITSTRING_VC;
        String issuanceId = "proc-123";
        String token = "token-abc";

        assertThrows(RuntimeException.class, () -> workflow.allocateEntry(null, format, issuanceId, token, "https://issuer.example.com"));

        verifyNoInteractions(statusListProvider);
    }

    @Test
    void allocateEntry_tokenJwtFormat_delegatesToProvider() {
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        StatusListFormat format = StatusListFormat.TOKEN_JWT;
        String issuanceId = "proc-456";
        String token = "token-xyz";

        StatusListEntry entry = StatusListEntry.builder()
                .id("https://issuer.example/token/v1/credentials/status/10#5")
                .type("TokenStatusList")
                .statusPurpose(purpose)
                .statusListIndex("5")
                .statusListCredential("https://issuer.example/token/v1/credentials/status/10")
                .build();

        when(statusListProvider.allocateEntry(purpose, format, issuanceId, token, "https://issuer.example.com"))
                .thenReturn(Mono.just(entry));

        StepVerifier.create(workflow.allocateEntry(purpose, format, issuanceId, token, "https://issuer.example.com"))
                .assertNext(e -> {
                    assertEquals("TokenStatusList", e.type());
                    assertEquals("5", e.statusListIndex());
                })
                .verifyComplete();

        verify(statusListProvider).allocateEntry(purpose, format, issuanceId, token, "https://issuer.example.com");
    }

    @Test
    void releaseEntry_whenSuccess_completesAndCallsProvider() {
        String issuanceId = "issuance-123";

        when(statusListProvider.releaseEntry(issuanceId)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.releaseEntry(issuanceId)).verifyComplete();

        verify(statusListProvider).releaseEntry(issuanceId);
        verifyNoMoreInteractions(statusListProvider);
    }

    @Test
    void releaseEntry_whenProviderErrors_propagatesErrorAndCallsProvider() {
        String issuanceId = "issuance-123";
        RuntimeException ex = new RuntimeException("db down");

        when(statusListProvider.releaseEntry(issuanceId)).thenReturn(Mono.error(ex));

        StepVerifier.create(workflow.releaseEntry(issuanceId))
                .expectErrorMatches(e -> e instanceof RuntimeException && "db down".equals(e.getMessage()))
                .verify();

        verify(statusListProvider).releaseEntry(issuanceId);
    }

    @Test
    void releaseEntry_whenIssuanceIdIsNull_throwsAndDoesNotCallProvider() {
        assertThrows(RuntimeException.class, () -> workflow.releaseEntry(null));

        verifyNoInteractions(statusListProvider);
    }

    @Test
    void getSignedStatusListCredential_whenSuccess_returnsCredentialAndCallsProvider() {
        Long listId = 10L;
        String signed = "signed-credential";

        when(statusListProvider.getSignedStatusListCredential(listId, StatusListFormat.BITSTRING_VC))
                .thenReturn(Mono.just(signed));

        StepVerifier.create(workflow.getSignedStatusListCredential(listId, StatusListFormat.BITSTRING_VC))
                .expectNext(signed)
                .verifyComplete();

        verify(statusListProvider).getSignedStatusListCredential(listId, StatusListFormat.BITSTRING_VC);
        verifyNoMoreInteractions(statusListProvider);
    }

    @Test
    void getSignedStatusListCredential_whenListIdIsNull_throwsAndDoesNotCallProvider() {
        assertThrows(RuntimeException.class, () -> workflow.getSignedStatusListCredential(null, StatusListFormat.BITSTRING_VC));

        verifyNoInteractions(statusListProvider);
    }

}
