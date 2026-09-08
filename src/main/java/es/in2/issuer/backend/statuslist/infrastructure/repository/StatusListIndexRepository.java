package es.in2.issuer.backend.statuslist.infrastructure.repository;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface StatusListIndexRepository extends ReactiveCrudRepository<StatusListIndex, Long> {

    Mono<StatusListIndex> findByIssuanceId(UUID issuanceId);

    Mono<Long> countByStatusListId(Long statusListId);

    // M1: releases an entry reserved by allocateEntry when the issuance it was reserved for never
    // completes (signing or persistence failed downstream) -- otherwise the idx stays permanently
    // reserved for an issuanceId nothing will ever reference again.
    Mono<Void> deleteByIssuanceId(UUID issuanceId);
}



