package es.in2.issuer.backend.shared.domain.model.enums;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeliveryModeTest {

    @Nested
    class Parse {

        @Test
        void parse_singleMode_returnsMatchingEnum() {
            Set<DeliveryMode> modes = DeliveryMode.parse("email");

            assertEquals(Set.of(DeliveryMode.EMAIL), modes);
        }

        @Test
        void parse_multipleModes_returnsAllMatchingEnums() {
            Set<DeliveryMode> modes = DeliveryMode.parse("direct,email");

            assertEquals(Set.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL), modes);
        }

        @Test
        void parse_duplicatesAndWhitespace_dedupesToSingleEntry() {
            Set<DeliveryMode> modes = DeliveryMode.parse(" email , email ");

            assertEquals(Set.of(DeliveryMode.EMAIL), modes);
        }

        @Test
        void parse_deduplicatesRepeatedModes() {
            Set<DeliveryMode> modes = DeliveryMode.parse("direct,direct,email");

            assertEquals(Set.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL), modes);
        }

        @Test
        void parse_singleModeRepeated_collapsesToOne() {
            Set<DeliveryMode> modes = DeliveryMode.parse("direct,direct");

            assertEquals(Set.of(DeliveryMode.DIRECT), modes);
        }

        @Test
        void parse_trimsWhitespaceAndIgnoresEmptySegments() {
            Set<DeliveryMode> modes = DeliveryMode.parse(" direct , , email ");

            assertEquals(Set.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL), modes);
        }

        @Test
        void parse_unknownMode_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse("carrier-pigeon"));
        }

        @Test
        void parse_blankInput_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse("   "));
        }

        @Test
        void parse_nullInput_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse(null));
        }

        @Test
        void parse_onlySeparators_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.parse(",,,"));
        }
    }

    @Nested
    class FromValue {

        @Test
        void fromValue_knownValue_returnsMatchingEnum() {
            assertEquals(Optional.of(DeliveryMode.UI), DeliveryMode.fromValue("ui"));
            assertEquals(Optional.of(DeliveryMode.EMAIL), DeliveryMode.fromValue("email"));
            assertEquals(Optional.of(DeliveryMode.DIRECT), DeliveryMode.fromValue("direct"));
        }

        @Test
        void fromValue_unknownValue_returnsEmpty() {
            assertEquals(Optional.empty(), DeliveryMode.fromValue("carrier-pigeon"));
        }
    }

    @Nested
    class IsDirect {

        @Test
        void isDirect_trueOnlyForDirectMode() {
            assertTrue(DeliveryMode.DIRECT.isDirect());
            assertFalse(DeliveryMode.EMAIL.isDirect());
            assertFalse(DeliveryMode.UI.isDirect());
        }
    }

    @Nested
    class ToCanonicalCsv {

        @Test
        void toCanonicalCsv_multipleModes_returnsAlphabeticallySortedCsv() {
            String csv = DeliveryMode.toCanonicalCsv(EnumSet.of(DeliveryMode.UI, DeliveryMode.DIRECT, DeliveryMode.EMAIL));

            assertEquals("direct,email,ui", csv);
        }

        @Test
        void toCanonicalCsv_singleMode_returnsThatModeValue() {
            String csv = DeliveryMode.toCanonicalCsv(Set.of(DeliveryMode.EMAIL));

            assertEquals("email", csv);
        }

        @Test
        void toCanonicalCsv_emptySet_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.toCanonicalCsv(Set.of()));
        }

        @Test
        void toCanonicalCsv_nullSet_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> DeliveryMode.toCanonicalCsv(null));
        }

        @Test
        void toCanonicalCsv_thenParse_roundTripsToOriginalSet() {
            Set<DeliveryMode> original = EnumSet.of(DeliveryMode.DIRECT, DeliveryMode.UI);

            Set<DeliveryMode> roundTripped = DeliveryMode.parse(DeliveryMode.toCanonicalCsv(original));

            assertEquals(original, roundTripped);
        }

        @Test
        void toCanonicalCsv_orderOfInputDoesNotAffectOutput() {
            String csvA = DeliveryMode.toCanonicalCsv(new LinkedHashSet<>(List.of(DeliveryMode.EMAIL, DeliveryMode.DIRECT)));
            String csvB = DeliveryMode.toCanonicalCsv(new LinkedHashSet<>(List.of(DeliveryMode.DIRECT, DeliveryMode.EMAIL)));

            assertEquals(csvA, csvB);
        }
    }
}
