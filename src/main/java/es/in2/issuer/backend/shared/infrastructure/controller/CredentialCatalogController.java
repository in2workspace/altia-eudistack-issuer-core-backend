package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.UpdateCredentialCatalogRequest;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_CATALOG_PATH;

/**
 * Admin API for the per-tenant credential catalog (EUD-72, US-02). Only a tenant
 * administrator (or SysAdmin) may use it. The tenant is always resolved from the
 * reactive context (subdomain / X-Tenant), never from the request body — see
 * {@code TenantDomainWebFilter}.
 *
 * <p>Reads and writes are authorized separately, matching {@code IssuanceController}:
 * <ul>
 *     <li><b>GET</b> requires {@code isTenantAdmin()} only. A SysAdmin operating from the
 *         platform tenant holds a cross-tenant read-only view, so denying reads would
 *         contradict both AC-03 and the meaning of {@code AuthorizationContext#readOnly}.</li>
 *     <li><b>PUT</b> additionally requires {@code canWrite()}, which rejects that same
 *         read-only SysAdmin.</li>
 * </ul>
 *
 * <p>An empty catalog is not a valid state: <b>PUT</b> with an empty
 * {@code enabledConfigurationIds} is rejected (400, bean validation) and <b>GET</b> answers
 * 404 when the tenant has no enabled configuration at all.
 */
@RestController
@RequestMapping(CREDENTIAL_CATALOG_PATH)
@RequiredArgsConstructor
public class CredentialCatalogController {

    private final AccessTokenService accessTokenService;
    private final TenantCredentialProfileService tenantCredentialProfileService;

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<List<CredentialCatalogEntryDto>> getCatalog(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return authorizeTenantAdminRead(authorizationHeader)
                .then(Mono.defer(tenantCredentialProfileService::getCatalog));
    }

    @PutMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<Void> updateCatalog(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @Valid @RequestBody UpdateCredentialCatalogRequest request) {
        return authorizeTenantAdminWrite(authorizationHeader)
                .then(Mono.defer(() -> tenantCredentialProfileService.updateCatalog(
                        request.enabledConfigurationIds(),
                        parseDeliveryModes(request.deliveryModesByConfigurationId()))));
    }

    /**
     * Raw strings, parsed here rather than in the DTO (task-planner decision): keeps
     * {@code DeliveryMode.parse} -- not this controller -- as the single source of truth for
     * which combinations are valid (ES-01 unknown value, ES-02 empty set).
     */
    private Map<String, Set<DeliveryMode>> parseDeliveryModes(Map<String, Set<String>> deliveryModesByConfigurationId) {
        if (deliveryModesByConfigurationId == null) {
            return Map.of();
        }
        return deliveryModesByConfigurationId.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> parseModes(entry.getKey(), entry.getValue())));
    }

    private Set<DeliveryMode> parseModes(String credentialConfigurationId, Set<String> rawModes) {
        try {
            return DeliveryMode.parse(String.join(",", rawModes));
        } catch (IllegalArgumentException e) {
            throw new InvalidDeliveryConfigException(
                    "Invalid delivery modes for credential configuration id '" + credentialConfigurationId + "': " + e.getMessage());
        }
    }

    private Mono<AuthorizationContext> authorizeTenantAdminRead(String authorizationHeader) {
        return accessTokenService.getAuthorizationContext(authorizationHeader)
                .flatMap(ctx -> {
                    if (!ctx.isTenantAdmin()) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.FORBIDDEN, "Tenant administrator role required"));
                    }
                    return Mono.just(ctx);
                });
    }

    private Mono<AuthorizationContext> authorizeTenantAdminWrite(String authorizationHeader) {
        return authorizeTenantAdminRead(authorizationHeader)
                .flatMap(ctx -> {
                    if (!ctx.canWrite()) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.FORBIDDEN, "Read-only access from platform tenant"));
                    }
                    return Mono.just(ctx);
                });
    }
}
