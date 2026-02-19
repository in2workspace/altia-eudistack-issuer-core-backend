package es.in2.issuer.backend.signing.domain.util;

import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.net.ConnectException;
import java.util.concurrent.TimeoutException;

public final class QtspRetryPolicy {

    private QtspRetryPolicy() {}

    public static boolean isRecoverable(Throwable throwable) {
        if (throwable instanceof WebClientResponseException ex) {
            return ex.getStatusCode().is5xxServerError();
        }
        return throwable instanceof ConnectException
                || throwable instanceof TimeoutException;
    }
}
