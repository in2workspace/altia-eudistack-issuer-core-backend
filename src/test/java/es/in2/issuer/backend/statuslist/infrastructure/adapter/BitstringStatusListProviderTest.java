package es.in2.issuer.backend.statuslist.infrastructure.adapter;


import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.statuslist.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.statuslist.domain.exception.*;
import es.in2.issuer.backend.statuslist.domain.factory.BitstringStatusListCredentialFactory;
import es.in2.issuer.backend.statuslist.domain.factory.TokenStatusListCredentialFactory;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusListData;
import es.in2.issuer.backend.statuslist.domain.model.StatusListIndexData;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.service.impl.BitstringStatusListRevocationService;
import es.in2.issuer.backend.statuslist.domain.util.BitstringEncoder;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusList;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndex;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListIndexRepository;
import es.in2.issuer.backend.statuslist.infrastructure.repository.StatusListRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BitstringStatusListProviderTest {


    @Mock
    private StatusListRepository statusListRepository;

    @Mock
    private StatusListIndexRepository statusListIndexRepository;

    @Mock
    private BitstringStatusListCredentialFactory statusListBuilder;

    @Mock
    private TokenStatusListCredentialFactory tokenStatusListBuilder;

    @Mock
    private BitstringStatusListRevocationService revocationService;

    @Mock
    private BitstringStatusListIndexReservation statusListIndexReservationService;

    @Mock
    private StatusListSigner statusListSigner;

    @Mock
    private IssuerFactory issuerFactory;

    @Mock
    private TransactionalOperator transactionalOperator;

    @InjectMocks
    private BitstringStatusListProvider bitstringStatusListProvider;

    @BeforeEach
    void setUp() {
        lenient().when(transactionalOperator.transactional(any(Mono.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    private static final Long TEST_LIST_ID = 1L;
    private static final String TEST_SIGNED_CREDENTIAL = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    private static final String TEST_ISSUANCE_ID = "550e8400-e29b-41d4-a716-446655440000";
    private static final String TEST_TOKEN = "test-token";
    private static final String TEST_ISSUER_URL = "https://issuer.example.com";
    private static final String TEST_ISSUER_DID = "did:example:issuer";
    private static final int TEST_IDX = 5;

    // ========== Tests for getSignedStatusListCredential ==========

    @Test
    void getSignedStatusListCredential_shouldReturnSignedCredential_whenListExistsWithSignedCredential() {
        // Arrange
        StatusList statusList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(statusList));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.getSignedStatusListCredential(TEST_LIST_ID, StatusListFormat.BITSTRING_VC))
                .expectNext(TEST_SIGNED_CREDENTIAL)
                .verifyComplete();

        verify(statusListRepository).findById(TEST_LIST_ID);
    }

    @Test
    void getSignedStatusListCredential_shouldThrowStatusListNotFoundException_whenStoredFormatIsNotTheOneServed() {
        // Both endpoints read the same table. A bitstring_vc row reached through the Token Status
        // List endpoint used to come back as a 200 carrying application/statuslist+jwt over a W3C
        // vc+jwt body; it must be a 404 instead.
        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(statusListRow("bitstring_vc")));

        StepVerifier.create(bitstringStatusListProvider.getSignedStatusListCredential(TEST_LIST_ID, StatusListFormat.TOKEN_JWT))
                .expectError(StatusListNotFoundException.class)
                .verify();

        verify(statusListRepository).findById(TEST_LIST_ID);
    }

    @Test
    void getSignedStatusListCredential_shouldThrowStatusListNotFoundException_whenListDoesNotExist() {
        // Arrange
        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.getSignedStatusListCredential(TEST_LIST_ID, StatusListFormat.BITSTRING_VC))
                .expectError(StatusListNotFoundException.class)
                .verify();

        verify(statusListRepository).findById(TEST_LIST_ID);
    }




    @Test
    void getSignedStatusListCredential_shouldThrowException_whenListIdIsNull() {
        // Act & Assert
        assertThatThrownBy(() -> bitstringStatusListProvider.getSignedStatusListCredential(null, StatusListFormat.BITSTRING_VC))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("listId");

        verifyNoInteractions(statusListRepository);
    }

    // ========== Tests for allocateEntry ==========

    @Test
    void allocateEntry_shouldReturnExistingEntry_whenProcedureAlreadyAllocated() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        StatusListIndex existingIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                10,
                procedureUuid,
                Instant.now()
        );

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("10")
                .statusListCredential(expectedListUrl)
                .build();

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.just(existingIndex));

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(statusListRow("bitstring_vc")));

        when(statusListBuilder.buildStatusListEntry(expectedListUrl, 10, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListIndexRepository).findByIssuanceId(procedureUuid);
        verify(statusListBuilder).buildStatusListEntry(expectedListUrl, 10, purpose);
    }

    @Test
    void allocateEntry_shouldFail_whenExistingAllocationIsOnAListOfAnotherFormat() {
        // A credential issued as dc+sd-jwt needs a token_jwt list: reusing the issuance's
        // bitstring_vc allocation would embed a /token/v1/... URI resolving to a W3C VC, which no
        // wallet can decode as a Status List Token. Fail instead of emitting that credential.
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.just(new StatusListIndex(1L, TEST_LIST_ID, 10, procedureUuid, Instant.now())));

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(statusListRow("bitstring_vc")));

        StepVerifier.create(bitstringStatusListProvider.allocateEntry(
                        StatusPurpose.REVOCATION, StatusListFormat.TOKEN_JWT, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectError(StatusListFormatMismatchException.class)
                .verify();

        verifyNoInteractions(tokenStatusListBuilder, statusListSigner);
    }

    private StatusList statusListRow(String format) {
        return new StatusList(
                TEST_LIST_ID, "revocation", format, "encodedList", TEST_SIGNED_CREDENTIAL,
                Instant.now(), Instant.now()
        );
    }

    @Test
    void allocateEntry_shouldAllocateNewEntry_whenNoPreviousAllocation() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        StatusList existingList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        StatusListIndexData reservedIndex = new StatusListIndexData(
                1L,
                TEST_LIST_ID,
                5,
                procedureUuid,
                Instant.now()
        );

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("5")
                .statusListCredential(expectedListUrl)
                .build();

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurposeAndFormat("revocation", "bitstring_vc"))
                .thenReturn(Mono.just(existingList));

        when(statusListIndexRepository.countByStatusListId(TEST_LIST_ID))
                .thenReturn(Mono.just(100L));

        when(statusListIndexReservationService.reserve(TEST_LIST_ID, TEST_ISSUANCE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(statusListBuilder.buildStatusListEntry(expectedListUrl, 5, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListIndexRepository).findByIssuanceId(procedureUuid);
        verify(statusListRepository).findLatestByPurposeAndFormat("revocation", "bitstring_vc");
        verify(statusListIndexRepository).countByStatusListId(TEST_LIST_ID);
        verify(statusListIndexReservationService).reserve(TEST_LIST_ID, TEST_ISSUANCE_ID);
        verify(statusListBuilder).buildStatusListEntry(expectedListUrl, 5, purpose);
    }

    @Test
    void allocateEntry_shouldThrowException_whenPurposeIsNull() {
        Mono<StatusListEntry> mono = monoFromCall(() ->
                bitstringStatusListProvider.allocateEntry(null, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("purpose");

        verifyNoInteractions(statusListIndexRepository);
    }

    @Test
    void allocateEntry_shouldThrowException_whenProcedureIdIsNull() {
        Mono<StatusListEntry> mono = monoFromCall(() ->
                bitstringStatusListProvider.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC, null, TEST_TOKEN, TEST_ISSUER_URL)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("issuanceId");

        verifyNoInteractions(statusListIndexRepository);
    }


    @Test
    void allocateEntry_shouldThrowException_whenTokenIsNull() {
        Mono<StatusListEntry> mono = monoFromCall(() ->
                bitstringStatusListProvider.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, null, TEST_ISSUER_URL)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("token");

        verifyNoInteractions(statusListIndexRepository);
    }


    @Test
    void allocateEntry_shouldThrowException_whenProcedureIdIsInvalidUUID() {
        Mono<StatusListEntry> mono = monoFromCall(() ->
                bitstringStatusListProvider.allocateEntry(StatusPurpose.REVOCATION, StatusListFormat.BITSTRING_VC, "invalid-uuid", TEST_TOKEN, TEST_ISSUER_URL)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(IllegalArgumentException.class);
    }


    @Test
    void allocateEntry_shouldCreateNewList_whenExistingListIsNearCapacity() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        Long newListId = 2L;

        StatusList existingList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        StatusList newListSaved = new StatusList(
                newListId,
                "revocation",
                "bitstring_vc",
                "newEncodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        StatusListIndexData reservedIndex = new StatusListIndexData(
                1L,
                newListId,
                0,
                procedureUuid,
                Instant.now()
        );

        String newListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + newListId;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("0")
                .statusListCredential(newListUrl)
                .build();

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurposeAndFormat("revocation", "bitstring_vc"))
                .thenReturn(Mono.just(existingList));

        // Simular que la llista està a prop de la capacitat (>90%)
        when(statusListIndexRepository.countByStatusListId(TEST_LIST_ID))
                .thenReturn(Mono.just(115000L)); // Més del 90% de 131072

        // Mock per crear la nova llista - s'anomena dues vegades durant el flux
        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(newListSaved));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(newListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(newListId), eq("vc+jwt")))
                .thenReturn(Mono.just("newSignedJwt"));

        when(statusListRepository.updateSignedCredential(newListId, "newSignedJwt"))
                .thenReturn(Mono.just(1));

        when(statusListIndexReservationService.reserve(newListId, TEST_ISSUANCE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(statusListBuilder.buildStatusListEntry(newListUrl, 0, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListIndexRepository).findByIssuanceId(procedureUuid);
        verify(statusListRepository).findLatestByPurposeAndFormat("revocation", "bitstring_vc");
        verify(statusListIndexRepository).countByStatusListId(TEST_LIST_ID);
        verify(statusListRepository, atLeastOnce()).save(any(StatusList.class));
        verify(issuerFactory, atLeastOnce()).createSimpleIssuer();
        verify(statusListSigner, atLeastOnce()).sign(anyMap(), eq(TEST_TOKEN), eq(newListId), eq("vc+jwt"));
        verify(statusListRepository, atLeastOnce()).updateSignedCredential(eq(newListId), anyString());
        verify(statusListIndexReservationService).reserve(newListId, TEST_ISSUANCE_ID);
    }

    @Test
    void allocateEntry_shouldAllocateNewEntry_whenNoListExists() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        StatusList newList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        StatusListIndexData reservedIndex = new StatusListIndexData(
                1L,
                TEST_LIST_ID,
                0,
                procedureUuid,
                Instant.now()
        );

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("0")
                .statusListCredential(expectedListUrl)
                .build();

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurposeAndFormat("revocation", "bitstring_vc"))
                .thenReturn(Mono.empty());

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(newList));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(expectedListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.just("signedJwt"));

        when(statusListRepository.updateSignedCredential(TEST_LIST_ID, "signedJwt"))
                .thenReturn(Mono.just(1));

        // Aquest mock és necessari perquè després de crear la llista, es fa un count
        when(statusListIndexRepository.countByStatusListId(TEST_LIST_ID))
                .thenReturn(Mono.just(0L));

        when(statusListIndexReservationService.reserve(TEST_LIST_ID, TEST_ISSUANCE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(statusListBuilder.buildStatusListEntry(expectedListUrl, 0, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListRepository).findLatestByPurposeAndFormat("revocation", "bitstring_vc");
        verify(statusListRepository, atLeastOnce()).save(any(StatusList.class));
        verify(issuerFactory, atLeastOnce()).createSimpleIssuer();
        verify(statusListSigner, atLeastOnce()).sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt"));
        verify(statusListIndexRepository).countByStatusListId(TEST_LIST_ID);
        verify(statusListIndexReservationService).reserve(TEST_LIST_ID, TEST_ISSUANCE_ID);
    }

    @Test
    void allocateEntry_shouldRollbackDeleteAndPropagateError_whenSigningFailsDuringCreateNewList() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusList savedList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurposeAndFormat("revocation", "bitstring_vc"))
                .thenReturn(Mono.empty());

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(savedList));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(expectedListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        RuntimeException signError = new RuntimeException("sign failed");
        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.error(signError));

        when(statusListRepository.deleteById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectErrorMatches(e -> e == signError)
                .verify();

        verify(statusListRepository).deleteById(TEST_LIST_ID);
    }

    @Test
    void allocateEntry_shouldPropagateOriginalError_whenRollbackDeleteAlsoFails() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusList savedList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurposeAndFormat("revocation", "bitstring_vc"))
                .thenReturn(Mono.empty());

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(savedList));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(expectedListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        RuntimeException signError = new RuntimeException("sign failed");
        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.error(signError));

        when(statusListRepository.deleteById(TEST_LIST_ID))
                .thenReturn(Mono.error(new RuntimeException("delete failed")));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectErrorMatches(e -> e == signError)
                .verify();

        verify(statusListRepository).deleteById(TEST_LIST_ID);
    }

    @Test
    void allocateEntry_shouldRollbackAndThrowStatusListSigningPersistenceException_whenUpdateSignedCredentialIsZero() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusList savedList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        String expectedListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurposeAndFormat("revocation", "bitstring_vc"))
                .thenReturn(Mono.empty());

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(savedList));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(expectedListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.just("jwt"));

        when(statusListRepository.updateSignedCredential(TEST_LIST_ID, "jwt"))
                .thenReturn(Mono.just(0));

        when(statusListRepository.deleteById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectError(StatusListSigningPersistenceException.class)
                .verify();

        verify(statusListRepository).deleteById(TEST_LIST_ID);
    }

    @Test
    void allocateEntry_shouldCreateNewListAndRetryReserve_whenIndexReservationExhausted() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusList existingList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        Long newListId = 2L;
        StatusList newListSaved = new StatusList(
                newListId,
                "revocation",
                "bitstring_vc",
                "newEncodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        StatusListIndexData reservedIndex = new StatusListIndexData(
                1L,
                newListId,
                7,
                procedureUuid,
                Instant.now()
        );

        String newListUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + newListId;

        StatusListEntry expectedEntry = StatusListEntry.builder()
                .id("urn:uuid:" + procedureUuid)
                .type("BitstringStatusListEntry")
                .statusPurpose(purpose)
                .statusListIndex("7")
                .statusListCredential(newListUrl)
                .build();

        SimpleIssuer simpleIssuer = SimpleIssuer.builder()
                .id(TEST_ISSUER_DID)
                .build();

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurposeAndFormat("revocation", "bitstring_vc"))
                .thenReturn(Mono.just(existingList));

        when(statusListIndexRepository.countByStatusListId(TEST_LIST_ID))
                .thenReturn(Mono.just(0L));

        // First reserve fails with exhausted
        when(statusListIndexReservationService.reserve(TEST_LIST_ID, TEST_ISSUANCE_ID))
                .thenReturn(Mono.error(new IndexReservationExhaustedException("", new Exception())));

        // Create new list
        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(newListSaved));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(eq(newListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(newListId), eq("vc+jwt")))
                .thenReturn(Mono.just("newJwt"));

        when(statusListRepository.updateSignedCredential(newListId, "newJwt"))
                .thenReturn(Mono.just(1));

        // Second reserve succeeds on the new list
        when(statusListIndexReservationService.reserve(newListId, TEST_ISSUANCE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(statusListBuilder.buildStatusListEntry(newListUrl, 7, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.BITSTRING_VC, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListIndexReservationService).reserve(TEST_LIST_ID, TEST_ISSUANCE_ID);
        verify(statusListIndexReservationService).reserve(newListId, TEST_ISSUANCE_ID);
    }

    @Test
    void getSignedStatusListCredential_shouldPropagateError_whenRepositoryFails() {
        // Arrange
        RuntimeException repoError = new RuntimeException("db down");

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.error(repoError));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.getSignedStatusListCredential(TEST_LIST_ID, StatusListFormat.BITSTRING_VC))
                .expectErrorMatches(e -> e == repoError)
                .verify();

        verify(statusListRepository).findById(TEST_LIST_ID);
        verifyNoMoreInteractions(statusListRepository);
    }

    @ParameterizedTest(name = "should throw when signed credential is missing: \"{0}\"")
    @NullSource
    @ValueSource(strings = {"", "   "})
    void getSignedStatusListCredential_shouldThrowException_whenSignedCredentialIsMissing(String signedCredential) {
        // Arrange
        StatusList statusList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                signedCredential,
                Instant.now(),
                Instant.now()
        );

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(statusList));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.getSignedStatusListCredential(TEST_LIST_ID, StatusListFormat.BITSTRING_VC))
                .expectError(SignedStatusListCredentialNotAvailableException.class)
                .verify();

        verify(statusListRepository).findById(TEST_LIST_ID);
    }

    // ========== Tests for allocateEntry with TOKEN_JWT format ==========

    @Test
    void allocateEntry_tokenJwtFormat_shouldUseTokenFactoryAndTokenStatusListBase() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        String tokenListUrl = TEST_ISSUER_URL + "/token/v1/credentials/status/" + TEST_LIST_ID;

        StatusList existingList = new StatusList(
                TEST_LIST_ID, "revocation", "token_jwt", "encodedList", "signedJwt",
                Instant.now(), Instant.now()
        );

        StatusListIndexData reservedIndex = new StatusListIndexData(
                1L, TEST_LIST_ID, TEST_IDX, procedureUuid, Instant.now()
        );

        StatusListEntry expectedEntry = new StatusListEntry(
                tokenListUrl + "#" + TEST_IDX,
                "TokenStatusListEntry",
                purpose,
                String.valueOf(TEST_IDX),
                tokenListUrl
        );

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        when(statusListRepository.findLatestByPurposeAndFormat("revocation", "token_jwt"))
                .thenReturn(Mono.just(existingList));

        when(statusListIndexRepository.countByStatusListId(TEST_LIST_ID))
                .thenReturn(Mono.just(0L));

        when(statusListIndexReservationService.reserve(TEST_LIST_ID, TEST_ISSUANCE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(tokenStatusListBuilder.buildStatusListEntry(tokenListUrl, TEST_IDX, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.TOKEN_JWT, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectNext(expectedEntry)
                .verifyComplete();

        verify(statusListRepository).findLatestByPurposeAndFormat("revocation", "token_jwt");
        verify(tokenStatusListBuilder).buildStatusListEntry(tokenListUrl, TEST_IDX, purpose);
        verifyNoInteractions(statusListBuilder);
    }

    @Test
    void allocateEntry_tokenJwtFormat_shouldCreateListWithStatuslistJwtTyp() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        Long newListId = 99L;
        String tokenListUrl = TEST_ISSUER_URL + "/token/v1/credentials/status/" + newListId;

        SimpleIssuer simpleIssuer = new SimpleIssuer(TEST_ISSUER_DID);

        StatusList newListSaved = new StatusList(
                newListId, "revocation", "token_jwt", "encodedList", null,
                Instant.now(), Instant.now()
        );

        StatusListIndexData reservedIndex = new StatusListIndexData(
                1L, newListId, 0, procedureUuid, Instant.now()
        );

        StatusListEntry expectedEntry = new StatusListEntry(
                tokenListUrl + "#0",
                "TokenStatusListEntry",
                purpose,
                "0",
                tokenListUrl
        );

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        // No existing TOKEN_JWT list → creates new one
        when(statusListRepository.findLatestByPurposeAndFormat("revocation", "token_jwt"))
                .thenReturn(Mono.empty());

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(newListSaved));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(tokenStatusListBuilder.buildUnsigned(eq(tokenListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("status_list", Map.of("bits", 1)));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(newListId), eq("statuslist+jwt")))
                .thenReturn(Mono.just("tokenJwt"));

        when(statusListRepository.updateSignedCredential(newListId, "tokenJwt"))
                .thenReturn(Mono.just(1));

        when(statusListIndexRepository.countByStatusListId(newListId))
                .thenReturn(Mono.just(0L));

        when(statusListIndexReservationService.reserve(newListId, TEST_ISSUANCE_ID))
                .thenReturn(Mono.just(reservedIndex));

        when(tokenStatusListBuilder.buildStatusListEntry(tokenListUrl, 0, purpose))
                .thenReturn(expectedEntry);

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.allocateEntry(purpose, StatusListFormat.TOKEN_JWT, TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectNext(expectedEntry)
                .verifyComplete();

        // Verify TOKEN_JWT-specific behavior: uses tokenStatusListBuilder, statuslist+jwt typ
        verify(tokenStatusListBuilder).buildUnsigned(eq(tokenListUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString());
        verify(statusListSigner).sign(anyMap(), eq(TEST_TOKEN), eq(newListId), eq("statuslist+jwt"));
        verify(tokenStatusListBuilder).buildStatusListEntry(tokenListUrl, 0, purpose);
        verifyNoInteractions(statusListBuilder);
    }

    @Test
    void revoke_shouldComplete_whenRevocationSucceeds() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        Instant updatedAt = Instant.parse("2026-01-01T00:00:00Z");

        StatusList currentRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                new BitstringEncoder().createEmptyEncodedList(131072),
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        StatusList updatedRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "updatedEncodedList",
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();

        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(currentRow));

        when(revocationService.applyRevocation(any(StatusListData.class), eq(TEST_IDX)))
                .thenReturn(new StatusListData(updatedRow.id(), updatedRow.purpose(), updatedRow.format(), updatedRow.encodedList(), updatedRow.signedCredential(), updatedRow.createdAt(), updatedRow.updatedAt()));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(listUrl, TEST_ISSUER_DID, "revocation", "updatedEncodedList"))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.just("jwt"));

        when(statusListRepository.updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        )).thenReturn(Mono.just(1));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .verifyComplete();

        verify(statusListIndexRepository).findByIssuanceId(procedureUuid);
        verify(statusListRepository).findById(TEST_LIST_ID);
        verify(revocationService).applyRevocation(any(StatusListData.class), eq(TEST_IDX));
        verify(statusListRepository).updateSignedAndEncodedIfUnchanged(eq(TEST_LIST_ID), anyString(), anyString(), eq(updatedAt));
    }

    @Test
    void revoke_shouldComplete_whenTokenIsNull() {
        // AD-1/EUD-225: system-triggered revocation has no caller token; the guard on
        // revoke() must not require it (unlike allocateEntry/createNewList, which still do).
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusListIndex listIndex = new StatusListIndex(1L, TEST_LIST_ID, TEST_IDX, procedureUuid, Instant.now());
        Instant updatedAt = Instant.parse("2026-01-01T00:00:00Z");

        StatusList currentRow = new StatusList(
                TEST_LIST_ID, "revocation", "bitstring_vc",
                new BitstringEncoder().createEmptyEncodedList(131072), TEST_SIGNED_CREDENTIAL, updatedAt, updatedAt
        );
        StatusList updatedRow = new StatusList(
                TEST_LIST_ID, "revocation", "bitstring_vc", "updatedEncodedList", TEST_SIGNED_CREDENTIAL, updatedAt, updatedAt
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();
        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByIssuanceId(procedureUuid)).thenReturn(Mono.just(listIndex));
        when(statusListRepository.findById(TEST_LIST_ID)).thenReturn(Mono.just(currentRow));
        when(revocationService.applyRevocation(any(StatusListData.class), eq(TEST_IDX)))
                .thenReturn(new StatusListData(updatedRow.id(), updatedRow.purpose(), updatedRow.format(), updatedRow.encodedList(), updatedRow.signedCredential(), updatedRow.createdAt(), updatedRow.updatedAt()));
        when(issuerFactory.createSimpleIssuer()).thenReturn(Mono.just(simpleIssuer));
        when(statusListBuilder.buildUnsigned(listUrl, TEST_ISSUER_DID, "revocation", "updatedEncodedList"))
                .thenReturn(Map.of("type", "StatusListCredential"));
        when(statusListSigner.sign(anyMap(), isNull(), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.just("jwt"));
        when(statusListRepository.updateSignedAndEncodedIfUnchanged(TEST_LIST_ID, "updatedEncodedList", "jwt", updatedAt))
                .thenReturn(Mono.just(1));

        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_ISSUANCE_ID, null, TEST_ISSUER_URL))
                .verifyComplete();

        verify(statusListSigner).sign(anyMap(), isNull(), eq(TEST_LIST_ID), eq("vc+jwt"));
    }

    @Test
    void revoke_shouldThrowStatusListIndexNotFoundException_whenNoIndexExists() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectError(StatusListIndexNotFoundException.class)
                .verify();

        verify(statusListIndexRepository).findByIssuanceId(procedureUuid);
        verifyNoInteractions(statusListRepository);
    }

    @Test
    void revoke_shouldThrowStatusListNotFoundException_whenStatusListDoesNotExist() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectError(StatusListNotFoundException.class)
                .verify();

        verify(statusListRepository).findById(TEST_LIST_ID);
        verifyNoInteractions(revocationService);
    }

    @Test
    void revoke_shouldCompleteWithoutUpdating_whenAlreadyRevoked() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        // Build an encodedList where TEST_IDX is already revoked (bit=1)
        BitstringEncoder enc = new BitstringEncoder();
        String empty = enc.createEmptyEncodedList(131072);

        StatusList baseRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                empty,
                TEST_SIGNED_CREDENTIAL,
                Instant.now(),
                Instant.now()
        );

        // Use the real revocation logic once to produce a list with the bit set,
        // then feed that to the provider so resolveRevocationCandidate sees it as already revoked.
        BitstringStatusListRevocationService realRevocation = new BitstringStatusListRevocationService();
        StatusListData baseData = new StatusListData(baseRow.id(), baseRow.purpose(), baseRow.format(), baseRow.encodedList(), baseRow.signedCredential(), baseRow.createdAt(), baseRow.updatedAt());
        StatusListData revokedData = realRevocation.applyRevocation(baseData, TEST_IDX);
        StatusList revokedRow = new StatusList(revokedData.id(), revokedData.purpose(), revokedData.format(), revokedData.encodedList(), revokedData.signedCredential(), revokedData.createdAt(), revokedData.updatedAt());

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(revokedRow));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .verifyComplete();

        verify(statusListIndexRepository).findByIssuanceId(procedureUuid);
        verify(statusListRepository).findById(TEST_LIST_ID);

        verifyNoInteractions(statusListSigner);
        verify(statusListRepository, never()).updateSignedAndEncodedIfUnchanged(anyLong(), anyString(), anyString(), any());
        verify(revocationService, never()).applyRevocation(any(), anyInt());
    }

    @Test
    void revoke_shouldRetryAndSucceed_whenOptimisticUpdateHappens() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        Instant updatedAt = Instant.parse("2026-01-01T00:00:00Z");

        StatusList currentRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                new BitstringEncoder().createEmptyEncodedList(131072),
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        StatusList updatedRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "updatedEncodedList",
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();
        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        // Will be called at least twice because of retry
        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(currentRow), Mono.just(currentRow));

        when(revocationService.applyRevocation(any(StatusListData.class), eq(TEST_IDX)))
                .thenReturn(new StatusListData(updatedRow.id(), updatedRow.purpose(), updatedRow.format(), updatedRow.encodedList(), updatedRow.signedCredential(), updatedRow.createdAt(), updatedRow.updatedAt()));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(listUrl, TEST_ISSUER_DID, "revocation", "updatedEncodedList"))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.just("jwt"));

        // First attempt: 0 rows updated -> OptimisticUpdateException
        // Second attempt: 1 row updated -> success
        when(statusListRepository.updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        )).thenReturn(Mono.just(0), Mono.just(1));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .verifyComplete();

        verify(statusListRepository, times(2)).updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        );
    }

    @Test
    void revoke_shouldThrowException_whenProcedureIdIsInvalidUUID() {
        Mono<Void> mono = monoFromCall(() ->
                bitstringStatusListProvider.revoke("invalid-uuid", TEST_TOKEN, TEST_ISSUER_URL)
        );

        assertThatThrownBy(mono::block)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid UUID string");

        verifyNoInteractions(statusListIndexRepository);
        verifyNoInteractions(statusListRepository);
    }


    @Test
    void revoke_shouldFailAfterMaxRetries_whenOptimisticUpdateNeverSucceeds() {
        // Arrange
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        StatusListIndex listIndex = new StatusListIndex(
                1L,
                TEST_LIST_ID,
                TEST_IDX,
                procedureUuid,
                Instant.now()
        );

        Instant updatedAt = Instant.parse("2026-01-01T00:00:00Z");

        StatusList currentRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                new BitstringEncoder().createEmptyEncodedList(131072),
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        StatusList updatedRow = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "updatedEncodedList",
                TEST_SIGNED_CREDENTIAL,
                updatedAt,
                updatedAt
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();
        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListIndexRepository.findByIssuanceId(procedureUuid))
                .thenReturn(Mono.just(listIndex));

        // Will be called once per attempt
        when(statusListRepository.findById(TEST_LIST_ID))
                .thenReturn(Mono.just(currentRow));

        when(revocationService.applyRevocation(any(StatusListData.class), eq(TEST_IDX)))
                .thenReturn(new StatusListData(updatedRow.id(), updatedRow.purpose(), updatedRow.format(), updatedRow.encodedList(), updatedRow.signedCredential(), updatedRow.createdAt(), updatedRow.updatedAt()));

        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));

        when(statusListBuilder.buildUnsigned(listUrl, TEST_ISSUER_DID, "revocation", "updatedEncodedList"))
                .thenReturn(Map.of("type", "StatusListCredential"));

        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.just("jwt"));

        // Always fails -> triggers OptimisticUpdateException every attempt
        when(statusListRepository.updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        )).thenReturn(Mono.just(0));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.revoke(TEST_ISSUANCE_ID, TEST_TOKEN, TEST_ISSUER_URL))
                .expectErrorMatches(e ->
                        e.getClass().getName().contains("RetryExhaustedException")
                                && e.getCause() instanceof OptimisticUpdateException
                )
                .verify();


        // maxAttempts=5 -> 5 invocations
        verify(statusListRepository, times(5)).updateSignedAndEncodedIfUnchanged(
                TEST_LIST_ID,
                "updatedEncodedList",
                "jwt",
                updatedAt
        );
    }

    // ========== Tests for Transactional createNewList ==========

    @Test
    void createNewList_shouldWrapSaveAndUpdateInTransactionalOperator_keepingSigningOutside() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        StatusListFormat format = StatusListFormat.BITSTRING_VC;

        StatusList savedList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();
        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(savedList));
        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));
        when(statusListBuilder.buildUnsigned(eq(listUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));
        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.just("signedJwt"));
        when(statusListRepository.updateSignedCredential(TEST_LIST_ID, "signedJwt"))
                .thenReturn(Mono.just(1));

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.createNewList(purpose, format, TEST_TOKEN, TEST_ISSUER_URL))
                .expectNextMatches(list -> list.id().equals(TEST_LIST_ID))
                .verifyComplete();

        // Verify that transactionalOperator.transactional was invoked at least twice (TX1: save, TX2: updateSignedCredential)
        verify(transactionalOperator, atLeast(2)).transactional(any(Mono.class));
        verify(statusListRepository).save(any(StatusList.class));
        verify(statusListRepository).updateSignedCredential(TEST_LIST_ID, "signedJwt");
        verify(statusListRepository, never()).deleteById(anyLong());
    }

    @Test
    void createNewList_shouldWrapRollbackDeleteInTransactionalOperator_whenSigningFails() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        StatusListFormat format = StatusListFormat.BITSTRING_VC;

        StatusList savedList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();
        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;
        RuntimeException signError = new RuntimeException("HTTP QTSP signing failed");

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(savedList));
        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));
        when(statusListBuilder.buildUnsigned(eq(listUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));
        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.error(signError));
        when(statusListRepository.deleteById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.createNewList(purpose, format, TEST_TOKEN, TEST_ISSUER_URL))
                .expectErrorMatches(e -> e == signError)
                .verify();

        // Verify transactionalOperator.transactional was invoked for save and for rollback delete
        verify(transactionalOperator, atLeast(2)).transactional(any(Mono.class));
        verify(statusListRepository).save(any(StatusList.class));
        verify(statusListRepository).deleteById(TEST_LIST_ID);
        verify(statusListRepository, never()).updateSignedCredential(anyLong(), anyString());
    }

    @Test
    void createNewList_shouldWrapRollbackDeleteInTransactionalOperator_whenUpdateSignedCredentialFails() {
        // Arrange
        StatusPurpose purpose = StatusPurpose.REVOCATION;
        StatusListFormat format = StatusListFormat.BITSTRING_VC;

        StatusList savedList = new StatusList(
                TEST_LIST_ID,
                "revocation",
                "bitstring_vc",
                "encodedList",
                null,
                Instant.now(),
                Instant.now()
        );

        SimpleIssuer simpleIssuer = SimpleIssuer.builder().id(TEST_ISSUER_DID).build();
        String listUrl = TEST_ISSUER_URL + "/w3c/v1/credentials/status/" + TEST_LIST_ID;

        when(statusListRepository.save(any(StatusList.class)))
                .thenReturn(Mono.just(savedList));
        when(issuerFactory.createSimpleIssuer())
                .thenReturn(Mono.just(simpleIssuer));
        when(statusListBuilder.buildUnsigned(eq(listUrl), eq(TEST_ISSUER_DID), eq("revocation"), anyString()))
                .thenReturn(Map.of("type", "StatusListCredential"));
        when(statusListSigner.sign(anyMap(), eq(TEST_TOKEN), eq(TEST_LIST_ID), eq("vc+jwt")))
                .thenReturn(Mono.just("jwt"));
        when(statusListRepository.updateSignedCredential(TEST_LIST_ID, "jwt"))
                .thenReturn(Mono.just(0));
        when(statusListRepository.deleteById(TEST_LIST_ID))
                .thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(bitstringStatusListProvider.createNewList(purpose, format, TEST_TOKEN, TEST_ISSUER_URL))
                .expectError(StatusListSigningPersistenceException.class)
                .verify();

        // Verify transactionalOperator.transactional was invoked for save, updateSignedCredential and rollback delete
        verify(transactionalOperator, atLeast(3)).transactional(any(Mono.class));
        verify(statusListRepository).save(any(StatusList.class));
        verify(statusListRepository).updateSignedCredential(TEST_LIST_ID, "jwt");
        verify(statusListRepository).deleteById(TEST_LIST_ID);
    }

    @Test
    void releaseEntry_shouldDeleteTheIndexRowByIssuanceId() {
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);

        when(statusListIndexRepository.deleteByIssuanceId(procedureUuid)).thenReturn(Mono.empty());

        StepVerifier.create(bitstringStatusListProvider.releaseEntry(TEST_ISSUANCE_ID)).verifyComplete();

        verify(statusListIndexRepository).deleteByIssuanceId(procedureUuid);
    }

    @Test
    void releaseEntry_shouldPropagateRepositoryFailure() {
        UUID procedureUuid = UUID.fromString(TEST_ISSUANCE_ID);
        RuntimeException dbError = new RuntimeException("connection reset");

        when(statusListIndexRepository.deleteByIssuanceId(procedureUuid)).thenReturn(Mono.error(dbError));

        StepVerifier.create(bitstringStatusListProvider.releaseEntry(TEST_ISSUANCE_ID))
                .expectErrorMatches(e -> e instanceof RuntimeException && "connection reset".equals(e.getMessage()))
                .verify();
    }

    @Test
    void releaseEntry_shouldThrow_whenIssuanceIdIsNull() {
        assertThatThrownBy(() -> monoFromCall(() -> bitstringStatusListProvider.releaseEntry(null)).block())
                .isInstanceOf(RuntimeException.class);

        verifyNoInteractions(statusListIndexRepository);
    }

    private static <T> Mono<T> monoFromCall(Supplier<Mono<T>> call) {
        try {
            return call.get();
        } catch (Throwable t) {
            return Mono.error(t);
        }
    }

}