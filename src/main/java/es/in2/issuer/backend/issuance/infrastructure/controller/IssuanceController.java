package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dtos.UpdateIssuanceStatusRequest;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceHttpResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;

@Slf4j
@RestController
@RequestMapping(ISSUANCES_PATH)
@RequiredArgsConstructor
public class IssuanceController {

    private final IssuanceWorkflow issuanceWorkflow;
    private final IssuanceService issuanceService;
    private final AccessTokenService accessTokenService;
    private final RevocationWorkflow revocationWorkflow;
    private final UrlResolver urlResolver;
    private final IssuanceHttpEnvelopeMapper httpEnvelopeMapper;

    @PostMapping(
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<IssuanceHttpResponse>> createIssuance(
            @RequestHeader(name = "X-Id-Token", required = false) String idToken,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @Valid @RequestBody IssuanceRequest request,
            ServerWebExchange exchange) {
        String processId = UUID.randomUUID().toString();
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);
        String publicWalletBaseUrl = urlResolver.publicWalletBaseUrl(exchange);
        // X-Id-Token and Authorization are not interchangeable: the first is an optional identity
        // assertion read by the PDP, the second the caller's bearer credential. Direct delivery signs
        // inside this request and needs the latter -- reading the former for it made every direct
        // issuance of a profile that requires no X-Id-Token fail on a null token (EUD-168).
        return issuanceWorkflow.issueCredential(processId, request, idToken, authorizationHeader,
                        publicIssuerBaseUrl, publicWalletBaseUrl)
                .map(this::toResponseEntity);
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<IssuanceList> getAllIssuances(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return accessTokenService.getAuthorizationContext(authorizationHeader)
                .flatMap(issuanceService::getAllIssuancesVisibleFor);
    }

    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialDetails> getIssuance(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("id") String id) {
        return accessTokenService.getAuthorizationContext(authorizationHeader)
                .flatMap(ctx -> issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(ctx, id));
    }

    @PatchMapping(value = "/{id}",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> updateIssuanceStatus(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("id") String id,
            @Valid @RequestBody UpdateIssuanceStatusRequest request,
            ServerWebExchange exchange) {
        String processId = UUID.randomUUID().toString();
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);
        return accessTokenService.getAuthorizationContext(authorizationHeader)
                .flatMap(ctx -> {
                    if (!ctx.canWrite()) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.FORBIDDEN, "Read-only access from platform tenant"));
                    }
                    return switch (request.status()) {
                        case WITHDRAWN -> authorizeAndWithdraw(ctx, id);
                        case REVOKED -> revocationWorkflow.revoke(processId, authorizationHeader, id, null, publicIssuerBaseUrl);
                        case ARCHIVED -> authorizeAndArchive(ctx, id);
                        default -> Mono.error(new ResponseStatusException(
                                HttpStatus.BAD_REQUEST,
                                "Unsupported target status: " + request.status()));
                    };
                });
    }

    private Mono<Void> authorizeAndArchive(AuthorizationContext ctx, String id) {
        if (ctx.isTenantAdmin()) {
            return issuanceService.archiveIssuance(id);
        }
        return issuanceService.getIssuanceById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .flatMap(issuance -> {
                    if (!ctx.organizationIdentifier().equals(issuance.getOrganizationIdentifier())) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.FORBIDDEN, "Cannot archive issuance from another organization"));
                    }
                    return issuanceService.archiveIssuance(id);
                });
    }

    private Mono<Void> authorizeAndWithdraw(AuthorizationContext ctx, String id) {
        if (ctx.isTenantAdmin()) {
            return issuanceService.withdrawIssuance(id);
        }
        // LEAR: verify ownership before withdrawing
        return issuanceService.getIssuanceById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .flatMap(issuance -> {
                    if (!ctx.organizationIdentifier().equals(issuance.getOrganizationIdentifier())) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.FORBIDDEN, "Cannot withdraw issuance from another organization"));
                    }
                    return issuanceService.withdrawIssuance(id);
                });
    }

    private ResponseEntity<IssuanceHttpResponse> toResponseEntity(IssuanceResponse response) {
        List<DeliveryResult> results = response.deliveryResults();
        boolean hasDeliveryResults = results != null && !results.isEmpty();

        log.debug("Issuance process completed. Signed Credential present: {}, Credential Offer URI present: {}, delivery results: {}",
                response.signedCredential() != null, response.credentialOfferUri() != null,
                hasDeliveryResults ? results.size() : 0);

        // No channel executed at all -- the pre-flight guard rejected before anything ran. Not
        // modeled by D-5's responses[] envelope (that requires >=1 executed channel); every guard
        // rejection is a thrown exception handled by IssuanceExceptionHandler before this method is
        // ever reached, so this is the harmless residual default for an empty/absent result set.
        if (!hasDeliveryResults) {
            return ResponseEntity.accepted().build();
        }

        IssuanceHttpResponse body = httpEnvelopeMapper.toHttpResponse(response);
        boolean anyChannelFailed = results.stream().anyMatch(r -> r.status() == DeliveryResult.DeliveryOutcome.FAILED);
        boolean anyChannelSucceeded = results.stream().anyMatch(r -> r.status() != DeliveryResult.DeliveryOutcome.FAILED);

        // Mixed outcome (EUD-167 D-5 / AD-1 B, RFC 4918 §11.1/§13): at least one requested channel
        // completed and at least one failed, regardless of which channel is which -- supersedes
        // EUD-168's AD-11 (500 whenever the direct mode failed, 200 whenever it didn't), which predates
        // and conflicts with D-5's general contract (PO decision, see EUD-167/spec-deltas.md D-6).
        // A request where nothing at all completed never reaches this branch -- the workflow re-raises
        // the original error upstream (assembleOutcome) so it renders as its own problem detail instead
        // of being flattened here.
        if (anyChannelFailed && anyChannelSucceeded) {
            log.warn("Partial issuance outcome (mixed delivery results): {}", results);
            return ResponseEntity.status(HttpStatus.MULTI_STATUS).body(body);
        }

        // Every requested channel failed (e.g. wallet-only with the wallet dependency down, direct
        // never attempted so assembleOutcome had nothing to re-raise): not mixed, not a success.
        if (anyChannelFailed) {
            log.warn("Issuance fully failed across all requested channels: {}", results);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
        }

        // D-5: 202 wallet-only is retired -- a fully successful request is always 200.
        return ResponseEntity.ok(body);
    }
}
