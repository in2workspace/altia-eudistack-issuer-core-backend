package es.in2.issuer.backend.shared.infrastructure.config.security;

import es.in2.issuer.backend.apiclient.infrastructure.security.IntakeCallerAuthorizationFilter;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import java.time.Duration;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationManager customAuthenticationManager;
    private final CorsFilterConfig corsConfig;
    private final AuditService auditService;

    private AuthenticationWebFilter customAuthenticationWebFilter(ProblemAuthenticationEntryPoint entryPoint) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(customAuthenticationManager);
        log.debug("customAuthenticationWebFilter - inside");

        authenticationWebFilter.setRequiresAuthenticationMatcher(
                ServerWebExchangeMatchers.pathMatchers(
                        // Issuance endpoints (unified)
                        ISSUANCES_PATH,
                        ISSUANCES_WILDCARD_PATH,
                        // Current caller role resolution (for frontends)
                        ME_PATH,
                        // Tenant admin delivery-config management (EUD-169)
                        DELIVERY_CONFIG_PATH,
                        // Tenant credential catalog admin (EUD-72)
                        CREDENTIAL_CATALOG_PATH,
                        // OID4VCI paths
                        OAUTH_TOKEN_PATH,
                        OID4VCI_CREDENTIAL_PATH,
                        OID4VCI_NOTIFICATION_PATH,
                        // Other authenticated paths
                        STATUS_LIST_PATH,
                        // Unattended issuance intake (EUD-75, US-02)
                        INTAKE_BASE_PATH,
                        INTAKE_PATH)
        );

        authenticationWebFilter.setServerAuthenticationConverter(new DualTokenServerAuthenticationConverter());
        authenticationWebFilter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(entryPoint));
        return authenticationWebFilter;
    }

    @Bean
    @Order(0)
    public SecurityWebFilterChain bootstrapFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(BOOTSTRAP_PATH))
                .authorizeExchange(exchange -> exchange.anyExchange().permitAll())
                .cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource()))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    @Bean
    @Order(0)
    public SecurityWebFilterChain credentialOfferRefreshFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(CREDENTIAL_OFFER_REFRESH_PATH))
                .authorizeExchange(exchange -> exchange.anyExchange().permitAll())
                .cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource()))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    @Bean
    @Order(1)
    public SecurityWebFilterChain unifiedFilterChain(
            ServerHttpSecurity http,
            ProblemAuthenticationEntryPoint entryPoint,
            ProblemAccessDeniedHandler deniedH
    ) {
        log.debug("unifiedFilterChain - inside");

        http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers(
                        // Issuance endpoints (unified)
                        ISSUANCES_PATH,
                        ISSUANCES_WILDCARD_PATH,
                        ISSUANCE_STATUS_CREDENTIALS,
                        // Current caller role resolution
                        ME_PATH,
                        // Tenant admin delivery-config management (EUD-169)
                        DELIVERY_CONFIG_PATH,
                        // Tenant credential catalog admin (EUD-72)
                        CREDENTIAL_CATALOG_PATH,
                        // Public OID4VCI paths
                        CORS_OID4VCI_PATH,
                        VCI_PATH,
                        WELL_KNOWN_PATH,
                        OAUTH_PATH,
                        // Other paths
                        STATUS_LIST_PATH,
                        TOKEN_STATUS_LIST_PATH,
                        HEALTH_PATH,
                        PROMETHEUS_PATH,
                        SPRINGDOC_PATH,
                        // Unattended issuance intake (EUD-75, US-02)
                        INTAKE_BASE_PATH,
                        INTAKE_PATH
                ))
                .cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource()))
                .headers(headers -> headers
                        // SEC-05: Security response headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'none'; frame-ancestors 'none'"))
                        .frameOptions(fo -> fo.mode(
                                XFrameOptionsServerHttpHeadersWriter.Mode.DENY))
                        .hsts(hsts -> hsts.includeSubdomains(true)
                                .maxAge(Duration.ofDays(365)))
                        .referrerPolicy(rp -> rp.policy(
                                ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        .permissionsPolicy(pp -> pp.policy(
                                "geolocation=(), camera=(), microphone=()"))
                        .contentTypeOptions(Customizer.withDefaults())
                )
                .authorizeExchange(exchange -> exchange
                        // Public endpoints (no auth)
                        .pathMatchers(HttpMethod.GET,
                                CORS_CREDENTIAL_OFFER_PATH,
                                CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH,
                                CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_WILDCARD_PATH,
                                AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH,
                                AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_WILDCARD_PATH,
                                OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH,
                                OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_WILDCARD_PATH,
                                JWKS_PATH,
                                HEALTH_PATH,
                                PROMETHEUS_PATH,
                                SPRINGDOC_PATH,
                                STATUS_LIST_PATH,
                                TOKEN_STATUS_LIST_PATH,
                                ISSUANCE_STATUS_CREDENTIALS
                        ).permitAll()
                        .pathMatchers(HttpMethod.POST, OAUTH_TOKEN_PATH).permitAll()
                        .pathMatchers(HttpMethod.POST, OID4VCI_PAR_PATH).permitAll()
                        .pathMatchers(HttpMethod.GET, OID4VCI_AUTHORIZE_PATH).permitAll()
                        .pathMatchers(HttpMethod.POST, OID4VCI_NONCE_PATH).permitAll()
                        // Authenticated endpoints (all go through CustomAuthenticationManager)
                        .anyExchange().authenticated()
                )
                // CSRF disabled: all routes use Bearer token authentication (no cookies/sessions)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .addFilterAt(customAuthenticationWebFilter(entryPoint), SecurityWebFiltersOrder.AUTHENTICATION)
                // Wired manually (not a @Component) and placed after AUTHORIZATION so
                // it only ever runs on requests Spring's own .anyExchange().authenticated()
                // has already let through — see IntakeCallerAuthorizationFilter javadoc.
                .addFilterAfter(new IntakeCallerAuthorizationFilter(deniedH, auditService), SecurityWebFiltersOrder.AUTHORIZATION)
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedH)
                );
        log.debug("unifiedFilterChain - build");
        return http.build();
    }

}
