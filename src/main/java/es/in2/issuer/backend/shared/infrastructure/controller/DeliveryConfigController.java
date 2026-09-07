package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.DeliveryConfigProfileNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.DeliveryEligibilityResolver;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.service.TenantDeliveryConfigService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.controller.dto.DeliveryConfigDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.DELIVERY_CONFIG_PATH;

/**
 * Lets a TenantAdmin view and set which delivery modes are eligible for a
 * {@code credential_configuration_id} within their own tenant (FR-09).
 */
@RestController
@RequestMapping(DELIVERY_CONFIG_PATH)
@RequiredArgsConstructor
public class DeliveryConfigController {

    private final AccessTokenService accessTokenService;
    private final TenantCredentialProfileService tenantCredentialProfileService;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final TenantDeliveryConfigService tenantDeliveryConfigService;
    private final DeliveryEligibilityResolver deliveryEligibilityResolver;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<DeliveryConfigDto> getDeliveryConfig(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("credentialConfigurationId") String credentialConfigurationId) {
        return authorizeAndCheckProfile(authorizationHeader, credentialConfigurationId)
                .then(Mono.defer(() -> deliveryEligibilityResolver.resolveEligibleModes(credentialConfigurationId)))
                .map(modes -> toDto(credentialConfigurationId, modes));
    }

    @PutMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<DeliveryConfigDto> setDeliveryConfig(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("credentialConfigurationId") String credentialConfigurationId,
            @RequestBody DeliveryConfigDto request) {
        return authorizeAndCheckProfile(authorizationHeader, credentialConfigurationId)
                .then(Mono.defer(() -> {
                    Set<DeliveryMode> modes = parseModes(credentialConfigurationId, request);
                    return tenantDeliveryConfigService.setEligibleModes(credentialConfigurationId, modes)
                            .thenReturn(toDto(credentialConfigurationId, modes));
                }));
    }

    private Mono<Void> authorizeAndCheckProfile(String authorizationHeader, String credentialConfigurationId) {
        return authorizeTenantAdmin(authorizationHeader)
                .then(Mono.defer(() -> assertProfileAllowed(credentialConfigurationId)));
    }

    private Mono<Void> authorizeTenantAdmin(String authorizationHeader) {
        return accessTokenService.getAuthorizationContext(authorizationHeader)
                .flatMap(ctx -> {
                    if (ctx.isTenantAdmin()) {
                        return Mono.empty();
                    }
                    return Mono.error(new ResponseStatusException(
                            HttpStatus.FORBIDDEN, "TenantAdmin role is required to manage delivery configuration"));
                });
    }

    private Mono<Void> assertProfileAllowed(String credentialConfigurationId) {
        if (credentialProfileRegistry.getByConfigurationId(credentialConfigurationId) == null) {
            return Mono.error(new DeliveryConfigProfileNotFoundException(
                    "Unknown credential_configuration_id: " + credentialConfigurationId));
        }
        return tenantCredentialProfileService.isProfileAllowed(credentialConfigurationId)
                .flatMap(allowed -> {
                    if (Boolean.TRUE.equals(allowed)) {
                        return Mono.empty();
                    }
                    return Mono.error(new DeliveryConfigProfileNotFoundException(
                            "credential_configuration_id is not enabled for this tenant: " + credentialConfigurationId));
                });
    }

    private Set<DeliveryMode> parseModes(String credentialConfigurationId, DeliveryConfigDto request) {
        String bodyConfigId = request.credentialConfigurationId();
        if (bodyConfigId != null && !bodyConfigId.equals(credentialConfigurationId)) {
            throw new InvalidDeliveryConfigException(
                    "credential_configuration_id in the request body ('" + bodyConfigId
                            + "') does not match the path ('" + credentialConfigurationId + "')");
        }
        List<String> rawModes = request.eligibleModes();
        if (rawModes == null || rawModes.isEmpty()) {
            throw new InvalidDeliveryConfigException("eligible_modes must contain at least one delivery mode");
        }
        try {
            return DeliveryMode.parse(String.join(",", rawModes));
        } catch (IllegalArgumentException e) {
            throw new InvalidDeliveryConfigException(e.getMessage());
        }
    }

    private DeliveryConfigDto toDto(String credentialConfigurationId, Set<DeliveryMode> modes) {
        List<String> canonical = modes.stream()
                .map(m -> m.value)
                .sorted()
                .toList();
        List<String> ceiling = schemaDeliveryCeiling.resolveEligibleModes(credentialConfigurationId).stream()
                .map(m -> m.value)
                .sorted()
                .toList();
        return DeliveryConfigDto.builder()
                .credentialConfigurationId(credentialConfigurationId)
                .eligibleModes(canonical)
                .schemaEligibleModes(ceiling)
                .build();
    }

}
