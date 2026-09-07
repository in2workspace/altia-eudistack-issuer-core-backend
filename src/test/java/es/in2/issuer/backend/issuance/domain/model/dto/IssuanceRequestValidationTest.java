package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TD-06 (code-review): {@code delivery} is bounded at the DTO boundary so a value carrying CRLF/
 * control characters is rejected before it ever reaches {@code DeliveryMode.parse} or the
 * {@code log.error} in {@code IssuanceWorkflowImpl} that interpolates it raw.
 */
class IssuanceRequestValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    private IssuanceRequest requestWithDelivery(String delivery) {
        return IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(OBJECT_MAPPER.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery(delivery)
                .build();
    }

    @Test
    void delivery_Null_IsValid() {
        assertThat(validator.validate(requestWithDelivery(null))).isEmpty();
    }

    @Test
    void delivery_SingleMode_IsValid() {
        assertThat(validator.validate(requestWithDelivery("direct"))).isEmpty();
    }

    @Test
    void delivery_HybridCsv_IsValid() {
        assertThat(validator.validate(requestWithDelivery("direct,email,ui"))).isEmpty();
    }

    @Test
    void delivery_WithWhitespaceAroundCommas_IsValid() {
        assertThat(validator.validate(requestWithDelivery(" direct , email "))).isEmpty();
    }

    @Test
    void delivery_ContainingCarriageReturnLineFeed_IsRejected() {
        Set<ConstraintViolation<IssuanceRequest>> violations =
                validator.validate(requestWithDelivery("direct\r\nX-Forged-Header: 1"));

        assertThat(violations)
                .isNotEmpty()
                .anyMatch(v -> v.getPropertyPath().toString().equals("delivery"));
    }

    @Test
    void delivery_ExceedingMaxLength_IsRejected() {
        String tooLong = "direct,".repeat(20);

        Set<ConstraintViolation<IssuanceRequest>> violations =
                validator.validate(requestWithDelivery(tooLong));

        assertThat(violations)
                .isNotEmpty()
                .anyMatch(v -> v.getPropertyPath().toString().equals("delivery"));
    }

    @Test
    void delivery_ContainingDigitsOrSymbols_IsRejected() {
        Set<ConstraintViolation<IssuanceRequest>> violations =
                validator.validate(requestWithDelivery("direct;drop"));

        assertThat(violations)
                .isNotEmpty()
                .anyMatch(v -> v.getPropertyPath().toString().equals("delivery"));
    }
}
