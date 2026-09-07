package es.in2.issuer.backend.shared.infrastructure.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Duration;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;

@Slf4j
@Component
@Order(1)
public class IdempotencyFilter implements WebFilter {

    private static final String IDEMPOTENCY_HEADER = "X-Idempotency-Key";

    private final IssuanceMetrics issuanceMetrics;
    private final AccessTokenService accessTokenService;
    private final Cache<String, CachedResponse> cache;

    public IdempotencyFilter(
            @Value("${issuer.api.idempotency-ttl-seconds:3600}") long ttlSeconds,
            IssuanceMetrics issuanceMetrics,
            AccessTokenService accessTokenService) {
        this.issuanceMetrics = issuanceMetrics;
        this.accessTokenService = accessTokenService;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(ttlSeconds))
                .maximumSize(10_000)
                .build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (!ISSUANCES_PATH.equals(path)) {
            return chain.filter(exchange);
        }

        String idempotencyKey = exchange.getRequest().getHeaders().getFirst(IDEMPOTENCY_HEADER);
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            return chain.filter(exchange);
        }

        String tenantHeader = exchange.getRequest().getHeaders().getFirst(X_TENANT_HEADER);
        String tenantScope = (tenantHeader == null || tenantHeader.isBlank())
                ? exchange.getRequest().getURI().getHost()
                : tenantHeader;

        // The cache key MUST bind to the caller's own identity (security finding H2): scoping by
        // tenant alone lets any organization within the same tenant collide on a shared or
        // predictable idempotency key and receive another organization's cached response --
        // including a directly-delivered signed credential (EUD-167), which exists nowhere else
        // (it is never persisted, only cached here). The organization id is read straight from the
        // bearer token rather than from a security context populated upstream, so this does not
        // depend on this filter's position relative to the authentication filter chain. A request
        // whose token cannot be resolved skips idempotency caching entirely instead of risking a
        // wrong key -- it is rejected downstream on its own merits regardless.
        String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return chain.filter(exchange);
        }

        String finalTenantScope = tenantScope;
        return accessTokenService.getOrganizationId(authorizationHeader)
                .flatMap(organizationId -> handleIdempotentRequest(
                        exchange, chain, finalTenantScope, organizationId, idempotencyKey))
                .onErrorResume(ex -> {
                    log.warn("Could not resolve caller organization for idempotency scoping, skipping cache: {}",
                            ex.toString());
                    return chain.filter(exchange);
                });
    }

    private Mono<Void> handleIdempotentRequest(ServerWebExchange exchange, WebFilterChain chain,
                                                String tenantScope, String organizationId, String idempotencyKey) {
        String scopedIdempotencyKey = tenantScope + ":" + organizationId + ":" + idempotencyKey;

        CachedResponse cached = cache.getIfPresent(scopedIdempotencyKey);
        if (cached != null) {
            log.info("Idempotency key '{}' already processed, returning cached status {}", idempotencyKey, cached.status);
            issuanceMetrics.recordIdempotencyCacheHit();
            exchange.getResponse().setStatusCode(cached.status);
            if (cached.locationHeader != null) {
                exchange.getResponse().getHeaders().setLocation(URI.create(cached.locationHeader));
            }
            if (cached.body != null && cached.body.length > 0) {
                if (cached.contentType != null) {
                    exchange.getResponse().getHeaders().setContentType(cached.contentType);
                }
                DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(cached.body);
                return exchange.getResponse().writeWith(Mono.just(buffer));
            }
            return exchange.getResponse().setComplete();
        }

        CapturingResponseDecorator decorator = new CapturingResponseDecorator(exchange);
        return chain.filter(exchange.mutate().response(decorator).build())
                .then(Mono.fromRunnable(() -> {
                    HttpStatusCode status = exchange.getResponse().getStatusCode();
                    String location = exchange.getResponse().getHeaders().getFirst("Location");
                    if (status != null && status.is2xxSuccessful()) {
                        cache.put(scopedIdempotencyKey, new CachedResponse(
                                status, location, decorator.capturedBody, decorator.capturedContentType));
                    }
                }));
    }

    private static final class CapturingResponseDecorator extends ServerHttpResponseDecorator {

        private byte[] capturedBody;
        private MediaType capturedContentType;

        private CapturingResponseDecorator(ServerWebExchange exchange) {
            super(exchange.getResponse());
        }

        @Override
        public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
            return DataBufferUtils.join(body)
                    .flatMap(dataBuffer -> {
                        byte[] bytes = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(bytes);
                        DataBufferUtils.release(dataBuffer);
                        this.capturedBody = bytes;
                        this.capturedContentType = getHeaders().getContentType();
                        return super.writeWith(Mono.just(bufferFactory().wrap(bytes)));
                    });
        }
    }

    private record CachedResponse(HttpStatusCode status, String locationHeader, byte[] body, MediaType contentType) {}
}
