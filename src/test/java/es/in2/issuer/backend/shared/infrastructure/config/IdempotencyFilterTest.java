package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IdempotencyFilterTest {

    private static final String IDEMPOTENCY_HEADER = "X-Idempotency-Key";
    private static final String TENANT_HEADER = "X-Tenant";
    private static final String BODY = "{\"signed_credential\":\"signed-jwt\"}";

    @Mock
    private IssuanceMetrics issuanceMetrics;

    @Mock
    private AccessTokenService accessTokenService;

    private IdempotencyFilter filter;

    @BeforeEach
    void setUp() {
        filter = new IdempotencyFilter(3600, issuanceMetrics, accessTokenService);
        // Default: caller resolves to a single organization from the authenticated
        // SecurityContext. Tests exercising organization-scoping or failure override this.
        lenient().when(accessTokenService.getOrganizationIdFromCurrentSession())
                .thenReturn(Mono.just("org-a"));
    }

    /** Chain that writes a fixed JSON body once and counts how many times it runs. */
    private WebFilterChain writingChain(AtomicInteger invocations) {
        return exchange -> {
            invocations.incrementAndGet();
            exchange.getResponse().setStatusCode(HttpStatus.OK);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
            DataBuffer buffer = new DefaultDataBufferFactory().wrap(BODY.getBytes(StandardCharsets.UTF_8));
            return exchange.getResponse().writeWith(Mono.just(buffer));
        };
    }

    private String readBody(MockServerWebExchange exchange) {
        return exchange.getResponse().getBodyAsString().block();
    }

    @Test
    void replayWithSameKey_returnsCachedBody_andInvokesChainOnce() {
        String key = "idem-key-1";
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();
        assertEquals(BODY, readBody(first));

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(BODY, readBody(second));
        assertEquals(HttpStatus.OK, second.getResponse().getStatusCode());
        assertEquals(MediaType.APPLICATION_JSON, second.getResponse().getHeaders().getContentType());
        assertEquals(1, invocations.get());
        verify(issuanceMetrics).recordIdempotencyCacheHit();
    }

    @Test
    void sameKeyDifferentTenants_doesNotCollide() {
        String sharedKey = "shared-idem-key";
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange tenantA = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, sharedKey)
                        .header("X-Tenant", "tenant-a")
                        .build());
        StepVerifier.create(filter.filter(tenantA, chain)).verifyComplete();

        MockServerWebExchange tenantB = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, sharedKey)
                        .header("X-Tenant", "tenant-b")
                        .build());
        StepVerifier.create(filter.filter(tenantB, chain)).verifyComplete();

        // Different tenants reusing the same idempotency key (same organization) must NOT share the cache entry.
        assertEquals(2, invocations.get());
        assertEquals(BODY, readBody(tenantB));
    }

    @Test
    void sameKeyDifferentOrganizationsSameTenant_doesNotCollide() {
        // Regression test for H2: same tenant, same idempotency key, but two different
        // organizations -- reusing a key across organizations of the same tenant must not
        // return one organization's cached response (e.g. a signed credential) to the other.
        String sharedKey = "shared-idem-key";
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);
        when(accessTokenService.getOrganizationIdFromCurrentSession())
                .thenReturn(Mono.just("org-a"), Mono.just("org-b"));

        MockServerWebExchange orgA = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, sharedKey)
                        .header(TENANT_HEADER, "tenant-a")
                        .build());
        StepVerifier.create(filter.filter(orgA, chain)).verifyComplete();

        MockServerWebExchange orgB = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, sharedKey)
                        .header(TENANT_HEADER, "tenant-a")
                        .build());
        StepVerifier.create(filter.filter(orgB, chain)).verifyComplete();

        assertEquals(2, invocations.get());
        assertEquals(BODY, readBody(orgB));
        verify(issuanceMetrics, never()).recordIdempotencyCacheHit();
    }

    @Test
    void unresolvableSession_bypassesCacheGracefully() {
        // Covers both a missing/anonymous SecurityContext and a session whose token cannot be
        // resolved (W3, code-review): the organization now comes from the already-authenticated
        // SecurityContext rather than a fresh, unverified parse of the Authorization header, so
        // both cases collapse into the same "cannot resolve caller organization" fallback.
        String key = "unresolvable-session-key";
        when(accessTokenService.getOrganizationIdFromCurrentSession())
                .thenReturn(Mono.error(new InvalidTokenException()));
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        // A session that cannot be resolved must not crash the request nor be cached under a wrong key.
        assertEquals(2, invocations.get());
    }

    @Test
    void differentKeys_invokeChainEachTime() {
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).header(IDEMPOTENCY_HEADER, "key-a").build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).header(IDEMPOTENCY_HEADER, "key-b").build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(2, invocations.get());
    }

    @Test
    void sameKeyDifferentTenants_invokeChainEachTime() {
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, "same-key")
                        .header(TENANT_HEADER, "tenant-a")
                        .build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, "same-key")
                        .header(TENANT_HEADER, "tenant-b")
                        .build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(2, invocations.get());
    }

    @Test
    void noIdempotencyKey_bypassesCache() {
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(2, invocations.get());
    }
}
