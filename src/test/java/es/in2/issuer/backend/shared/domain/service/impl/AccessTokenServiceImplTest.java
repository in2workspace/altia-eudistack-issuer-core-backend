package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class AccessTokenServiceImplTest {

    @Mock
    private SignedJWT mockSignedJwt;
    @Mock
    private ObjectMapper mockObjectMapper;
    @Mock
    private IssuerProperties mockAppConfig;
    @Mock
    private TenantConfigService mockTenantConfigService;
    @InjectMocks
    private AccessTokenServiceImpl accessTokenServiceImpl;
    @Mock
    private TenantRegistryService mockTenantRegistryService;

    @Test
    void testGetCleanBearerToken_Valid() {
        String validHeader = "Bearer validToken123";
        Mono<String> result = accessTokenServiceImpl.getCleanBearerToken(validHeader);
        StepVerifier.create(result)
                .expectNext("validToken123")
                .verifyComplete();
    }

    @Test
    void testGetCleanBearerToken_Invalid() {
        String invalidHeader = "invalidToken123";
        Mono<String> result = accessTokenServiceImpl.getCleanBearerToken(invalidHeader);
        StepVerifier.create(result)
                .expectNext(invalidHeader)
                .verifyComplete();
    }

    @Test
    void testGetOrganizationId_ValidToken() throws JsonProcessingException {
        String validJwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoib3JnMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String expectedOrganizationId = "org123";
        String jwtPayload = "{\"mandator\":{\"organizationIdentifier\":\"" + expectedOrganizationId + "\"}}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            ObjectMapper realObjectMapper = new ObjectMapper();
            JsonNode vcJsonNode = realObjectMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(vcJsonNode);
            when(mockAppConfig.getManagementTokenOrgIdJsonPath()).thenReturn("mandator.organizationIdentifier");

            Mono<String> result = accessTokenServiceImpl.getOrganizationId("Bearer " + validJwtToken);

            StepVerifier.create(result)
                    .expectNext(expectedOrganizationId)
                    .verifyComplete();
        }
    }

    @Test
    void testGetOrganizationId_InvalidToken() {
        String invalidJwtToken = "invalid-jwt-token";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenThrow(new ParseException("Invalid token", 0));
            when(mockAppConfig.getManagementTokenOrgIdJsonPath()).thenReturn("mandator.organizationIdentifier");

            Mono<String> result = accessTokenServiceImpl.getOrganizationId("Bearer " + invalidJwtToken);

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }

    @Test
    void testGetOrganizationIdFromCurrentSession_ValidToken() throws ParseException, JsonProcessingException {
        String validJwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoib3JnMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String expectedOrganizationId = "org123";
        String jwtPayload = "{\"mandator\":{\"organizationIdentifier\":\"" + expectedOrganizationId + "\"}}";

        Jwt jwt = Jwt.withTokenValue(validJwtToken).header("alg", "HS256").claim("organizationIdentifier", expectedOrganizationId).build();
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt);
        SecurityContext securityContext = new SecurityContextImpl(jwtAuthenticationToken);

        try (MockedStatic<ReactiveSecurityContextHolder> mockedContextHolder = mockStatic(ReactiveSecurityContextHolder.class);
             MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {

            mockedContextHolder.when(ReactiveSecurityContextHolder::getContext)
                    .thenReturn(Mono.just(securityContext));

            // Create a JWSHeader and JWTClaimsSet from the payload
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSHeader.parse("{\"alg\":\"HS256\"}")).build();
            JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(jwtPayload);
            SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

            mockedJwtStatic.when(() -> SignedJWT.parse(validJwtToken)).thenReturn(signedJWT);
            ObjectMapper realObjectMapper = new ObjectMapper();
            JsonNode vcJsonNode = realObjectMapper.readTree(jwtPayload);
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(vcJsonNode);
            when(mockAppConfig.getManagementTokenOrgIdJsonPath()).thenReturn("mandator.organizationIdentifier");

            Mono<String> result = accessTokenServiceImpl.getOrganizationIdFromCurrentSession();

            StepVerifier.create(result)
                    .expectNext(expectedOrganizationId)
                    .verifyComplete();
        }
    }

    @Test
    void testGetOrganizationIdFromCurrentSession_InvalidToken() {
        String invalidJwtToken = "invalid-jwt-token";

        // Creamos un JWT con una reclamación mínima
        Jwt jwt = Jwt.withTokenValue(invalidJwtToken)
                .header("alg", "none")
                .claim("sub", "subject")
                .build();

        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt);
        SecurityContext securityContext = new SecurityContextImpl(jwtAuthenticationToken);

        try (MockedStatic<ReactiveSecurityContextHolder> mockedContextHolder = mockStatic(ReactiveSecurityContextHolder.class);
             MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {

            mockedContextHolder.when(ReactiveSecurityContextHolder::getContext)
                    .thenReturn(Mono.just(securityContext));

            mockedJwtStatic.when(() -> SignedJWT.parse(invalidJwtToken)).thenThrow(new ParseException("Invalid token", 0));
            when(mockAppConfig.getManagementTokenOrgIdJsonPath()).thenReturn("mandator.organizationIdentifier");

            Mono<String> result = accessTokenServiceImpl.getOrganizationIdFromCurrentSession();

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }


    @Test
    void testGetOrganizationIdFromCurrentSession_EmptyToken() {
        try (MockedStatic<ReactiveSecurityContextHolder> mockedContextHolder = mockStatic(ReactiveSecurityContextHolder.class)) {
            mockedContextHolder.when(ReactiveSecurityContextHolder::getContext)
                    .thenReturn(Mono.empty());

            Mono<String> result = accessTokenServiceImpl.getOrganizationIdFromCurrentSession();

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }

    @Test
    void testResolveAccessTokenContext_ValidToken(){
        // Arrange
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        String jti = "jti123";
        String issuanceId = UUID.randomUUID().toString();
        long exp = Instant.now().plusSeconds(3600).getEpochSecond();

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);

        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of(
                "jti", jti,
                "pid", issuanceId,
                "exp", exp
        ));

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic
                    .when(() -> JWSObject.parse(validToken))
                    .thenReturn(mockJwsObject);

            // Act
            Mono<AccessTokenContext> result =
                    accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            // Assert
            StepVerifier.create(result)
                    .expectNextMatches(context ->
                            validToken.equals(context.rawToken())
                                    && jti.equals(context.jti())
                                    && issuanceId.equals(context.issuanceId())
                    )
                    .verifyComplete();
        }
    }


    @Test
    void testResolveAccessTokenContext_TokenWithoutJti() {
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);
        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of("exp", 1234567890L)); // Missing jti

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic.when(() -> JWSObject.parse(validToken)).thenReturn(mockJwsObject);

            Mono<AccessTokenContext> result = accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            StepVerifier.create(result)
                    .expectErrorMatches(throwable ->
                            throwable instanceof InvalidTokenException &&
                                    throwable.getMessage().equals("Access token without jti")
                    )
                    .verify();
        }
    }

    @Test
    void testResolveAccessTokenContext_TokenWithoutExp() {
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);
        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of("jti", "jti123", "pid", "proc-1")); // Missing exp

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic.when(() -> JWSObject.parse(validToken)).thenReturn(mockJwsObject);

            Mono<AccessTokenContext> result = accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            StepVerifier.create(result)
                    .expectErrorMatches(throwable ->
                            throwable instanceof InvalidTokenException &&
                                    throwable.getMessage().equals("Access token without exp")
                    )
                    .verify();
        }
    }

    @Test
    void testResolveAccessTokenContext_ExpiredToken() {
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);
        long exp = System.currentTimeMillis() / 1000 - 3600; // 1 hour ago
        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of(
                "jti", "jti123",
                "pid", "proc-1",
                "exp", exp
        ));

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic.when(() -> JWSObject.parse(validToken)).thenReturn(mockJwsObject);

            Mono<AccessTokenContext> result = accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            StepVerifier.create(result)
                    .expectErrorMatches(throwable ->
                            throwable instanceof InvalidTokenException &&
                                    throwable.getMessage().equals("Access token expired")
                    )
                    .verify();
        }
    }

    @Test
    void testResolveAccessTokenContext_TokenWithoutPid() {
        String validToken = "validToken";
        String authorizationHeader = "Bearer " + validToken;

        JWSObject mockJwsObject = mock(JWSObject.class);
        Payload mockPayload = mock(Payload.class);
        when(mockJwsObject.getPayload()).thenReturn(mockPayload);
        when(mockPayload.toJSONObject()).thenReturn(Map.of(
                "jti", "jti123",
                "exp", System.currentTimeMillis() / 1000 + 3600
        ));

        try (MockedStatic<JWSObject> jwsObjectMockedStatic = mockStatic(JWSObject.class)) {
            jwsObjectMockedStatic.when(() -> JWSObject.parse(validToken)).thenReturn(mockJwsObject);

            Mono<AccessTokenContext> result = accessTokenServiceImpl.resolveAccessTokenContext(authorizationHeader);

            StepVerifier.create(result)
                    .expectErrorMatches(throwable ->
                            throwable instanceof InvalidTokenException &&
                                    throwable.getMessage().equals("Access token without pid")
                    )
                    .verify();
        }
    }

    // --- getAuthorizationContext tests ---

    @Test
    void testGetAuthorizationContext_SysAdmin_detected_by_organization_power() throws JsonProcessingException {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opB1Qfp7QDl4Ig";
        String orgId = "VATES-A15456585";
        String jwtPayload = "{\"mandator\":{\"organizationIdentifier\":\"" + orgId + "\"},"
                + "\"power\":[{\"type\":\"organization\",\"domain\":\"EUDISTACK\",\"function\":\"System\",\"action\":[\"Administration\"]}]}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(new ObjectMapper().readTree(jwtPayload));
            when(mockAppConfig.getManagementTokenOrgIdJsonPath()).thenReturn("mandator.organizationIdentifier");
            when(mockTenantRegistryService.getTenantType(anyString())).thenReturn(Mono.just("multi_org"));

            Mono<AuthorizationContext> result = accessTokenServiceImpl.getAuthorizationContext("Bearer " + token)
                    .contextWrite(ctx -> ctx.put("tenantDomain", "sandbox"));

            StepVerifier.create(result)
                    .expectNextMatches(ctx ->
                            ctx.role() == UserRole.SYSADMIN
                            && ctx.organizationIdentifier().equals(orgId)
                            && !ctx.readOnly()
                            && "multi_org".equals(ctx.tenantType())
                    )
                    .verifyComplete();
        }
    }

    @Test
    void testGetAuthorizationContext_SysAdmin_readOnly_from_platform() throws JsonProcessingException {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opB1Qfp7QDl4Ig";
        String jwtPayload = "{\"mandator\":{\"organizationIdentifier\":\"VATES-A15456585\"},"
                + "\"power\":[{\"type\":\"organization\",\"domain\":\"EUDISTACK\",\"function\":\"System\",\"action\":[\"Administration\"]}]}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(new ObjectMapper().readTree(jwtPayload));
            when(mockAppConfig.getManagementTokenOrgIdJsonPath()).thenReturn("mandator.organizationIdentifier");
            when(mockTenantRegistryService.getTenantType(anyString())).thenReturn(Mono.just("platform"));

            Mono<AuthorizationContext> result = accessTokenServiceImpl.getAuthorizationContext("Bearer " + token)
                    .contextWrite(ctx -> ctx.put("tenantDomain", "platform"));

            StepVerifier.create(result)
                    .expectNextMatches(ctx ->
                            ctx.role() == UserRole.SYSADMIN
                            && ctx.readOnly()
                            && !ctx.canWrite()
                            && "platform".equals(ctx.tenantType())
                    )
                    .verifyComplete();
        }
    }

    @Test
    void testGetAuthorizationContext_TenantAdmin_detected_by_adminOrgId() throws JsonProcessingException {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opB1Qfp7QDl4Ig";
        String adminOrgId = "ADMIN_ORG_123";
        String jwtPayload = "{\"mandator\":{\"organizationIdentifier\":\"" + adminOrgId + "\"},"
                + "\"power\":[{\"type\":\"domain\",\"domain\":\"DOME\",\"function\":\"Onboarding\",\"action\":[\"Execute\"]}]}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(new ObjectMapper().readTree(jwtPayload));
            when(mockAppConfig.getManagementTokenOrgIdJsonPath()).thenReturn("mandator.organizationIdentifier");
            when(mockAppConfig.getManagementTokenAdminPowerFunction()).thenReturn("Onboarding");
            when(mockAppConfig.getManagementTokenAdminPowerAction()).thenReturn("Execute");
            when(mockTenantConfigService.getStringOrThrow("admin_organization_id"))
                    .thenReturn(Mono.just(adminOrgId));
            when(mockTenantRegistryService.getTenantType(anyString())).thenReturn(Mono.just("multi_org"));

            Mono<AuthorizationContext> result = accessTokenServiceImpl.getAuthorizationContext("Bearer " + token)
                    .contextWrite(ctx -> ctx.put("tenantDomain", "dome"));

            StepVerifier.create(result)
                    .expectNextMatches(ctx ->
                            ctx.role() == UserRole.TENANT_ADMIN
                            && ctx.isTenantAdmin()
                            && ctx.canWrite()
                            && "multi_org".equals(ctx.tenantType())
                    )
                    .verifyComplete();
        }
    }

    @Test
    void testGetAuthorizationContext_LEAR_regularOrg() throws JsonProcessingException {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opB1Qfp7QDl4Ig";
        String orgId = "ACME-001";
        String jwtPayload = "{\"mandator\":{\"organizationIdentifier\":\"" + orgId + "\"},"
                + "\"power\":[{\"type\":\"domain\",\"domain\":\"DOME\",\"function\":\"Onboarding\",\"action\":[\"Execute\"]}]}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(new ObjectMapper().readTree(jwtPayload));
            when(mockAppConfig.getManagementTokenOrgIdJsonPath()).thenReturn("mandator.organizationIdentifier");
            lenient().when(mockAppConfig.getManagementTokenAdminPowerFunction()).thenReturn("Onboarding");
            lenient().when(mockAppConfig.getManagementTokenAdminPowerAction()).thenReturn("Execute");
            when(mockTenantConfigService.getStringOrThrow("admin_organization_id"))
                    .thenReturn(Mono.just("ADMIN_ORG_123"));

            Mono<AuthorizationContext> result = accessTokenServiceImpl.getAuthorizationContext("Bearer " + token)
                    .contextWrite(ctx -> ctx.put("tenantDomain", "dome"));
            when(mockTenantRegistryService.getTenantType(anyString())).thenReturn(Mono.just("simple"));

            StepVerifier.create(result)
                    .expectNextMatches(ctx ->
                            ctx.role() == UserRole.LEAR
                            && !ctx.isSysAdmin()
                            && !ctx.isTenantAdmin()
                            && ctx.canWrite()
                            && "simple".equals(ctx.tenantType())
                    )
                    .verifyComplete();
        }
    }

    // --- getTokenTenant tests ---

    @Test
    void testGetTokenTenant_ClaimPresent() throws JsonProcessingException {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opB1Qfp7QDl4Ig";
        String jwtPayload = "{\"tenant\":\"cgcom\",\"mandator\":{\"organizationIdentifier\":\"org-1\"}}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(new ObjectMapper().readTree(jwtPayload));

            Mono<String> result = accessTokenServiceImpl.getTokenTenant("Bearer " + token);

            StepVerifier.create(result)
                    .expectNext("cgcom")
                    .verifyComplete();
        }
    }

    @Test
    void testGetTokenTenant_ClaimAbsent_returnsEmpty() throws JsonProcessingException {
        String token = "eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opB1Qfp7QDl4Ig";
        String jwtPayload = "{\"mandator\":{\"organizationIdentifier\":\"org-1\"}}";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenReturn(mockSignedJwt);
            when(mockSignedJwt.getPayload()).thenReturn(new Payload(jwtPayload));
            when(mockObjectMapper.readTree(jwtPayload)).thenReturn(new ObjectMapper().readTree(jwtPayload));

            Mono<String> result = accessTokenServiceImpl.getTokenTenant("Bearer " + token);

            StepVerifier.create(result)
                    .verifyComplete();
        }
    }

    @Test
    void testGetTokenTenant_UnparseableToken_errorsInvalidToken() {
        String invalidJwtToken = "invalid-jwt-token";

        try (MockedStatic<SignedJWT> mockedJwtStatic = mockStatic(SignedJWT.class)) {
            mockedJwtStatic.when(() -> SignedJWT.parse(anyString())).thenThrow(new ParseException("Invalid token", 0));

            Mono<String> result = accessTokenServiceImpl.getTokenTenant("Bearer " + invalidJwtToken);

            StepVerifier.create(result)
                    .expectError(InvalidTokenException.class)
                    .verify();
        }
    }

}