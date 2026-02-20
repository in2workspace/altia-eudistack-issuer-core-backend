package es.in2.issuer.backend.signing.domain.model;

public enum JadesProfile {
    JADES_B_B,    // Baseline-B (sin timestamp)
    JADES_B_T,    // Baseline-T (con timestamp)
    JADES_B_LT,   // Baseline-LT (con evidencias de validación)
    JADES_B_LTA   // Baseline-LTA (archivo a largo plazo)
}