package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.spi.StatusListProvider;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.statuslist.domain.util.Preconditions.requireNonNullParam;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusListWorkflow {

    private final StatusListProvider statusListProvider;

    @Observed(name = "statuslist.allocate-entry", contextualName = "statuslist-allocate-entry")
    public Mono<StatusListEntry> allocateEntry(StatusPurpose purpose, StatusListFormat format,
                                               String issuanceId, String token,
                                               String publicIssuerBaseUrl) {
        log.info(
                "action=allocateStatusListEntry status=started purpose={} format={} issuanceId={}",
                purpose, format, issuanceId
        );
        requireNonNullParam(purpose, "purpose");
        requireNonNullParam(format, "format");

        return statusListProvider.allocateEntry(purpose, format, issuanceId, token, publicIssuerBaseUrl)
                .doOnSuccess(entry -> log.info(
                        "action=allocateStatusListEntry status=completed purpose={} format={} issuanceId={} listId={} idx={}",
                        purpose, format, issuanceId,
                        extractListId(entry), entry.statusListIndex()
                ))
                .doOnError(e -> log.warn(
                        "action=allocateStatusListEntry status=failed purpose={} format={} issuanceId={} error={}",
                        purpose, format, issuanceId, e.toString()
                ));
    }

    @Observed(name = "statuslist.release-entry", contextualName = "statuslist-release-entry")
    public Mono<Void> releaseEntry(String issuanceId) {
        log.info("action=releaseStatusListEntry status=started issuanceId={}", issuanceId);
        requireNonNullParam(issuanceId, "issuanceId");

        return statusListProvider.releaseEntry(issuanceId)
                .doOnSuccess(v -> log.info(
                        "action=releaseStatusListEntry status=completed issuanceId={}", issuanceId
                ))
                .doOnError(e -> log.warn(
                        "action=releaseStatusListEntry status=failed issuanceId={} error={}",
                        issuanceId, e.toString()
                ));
    }

    @Observed(name = "statuslist.get-signed-credential", contextualName = "statuslist-get-signed-credential")
    public Mono<String> getSignedStatusListCredential(Long listId, StatusListFormat expectedFormat) {
        requireNonNullParam(listId, "listId");
        requireNonNullParam(expectedFormat, "expectedFormat");
        return statusListProvider.getSignedStatusListCredential(listId, expectedFormat);
    }


    private String extractListId(StatusListEntry entry) {
        String cred = entry.statusListCredential();
        if (cred == null) return "unknown";
        int lastSlash = cred.lastIndexOf('/');
        return lastSlash >= 0 ? cred.substring(lastSlash + 1) : "unknown";
    }
}

