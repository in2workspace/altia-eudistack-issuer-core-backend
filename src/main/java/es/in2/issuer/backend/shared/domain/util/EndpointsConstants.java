package es.in2.issuer.backend.shared.domain.util;

public class EndpointsConstants {

    private EndpointsConstants() {
        throw new IllegalStateException("Utility class");
    }

    // Management Endpoints
    public static final String HEALTH_PATH = "/health";
    public static final String PROMETHEUS_PATH = "/prometheus";
    public static final String SPRINGDOC_BASE_PATH = "/springdoc";
    public static final String SPRINGDOC_PATH = SPRINGDOC_BASE_PATH+"/**";
    public static final String ISSUANCE_BASE_PATH = "/issuance/v1";
    public static final String OID4VCI_BASE_PATH = "/oid4vci/v1";
    public static final String WELL_KNOWN_BASE_PATH ="/.well-known";
    public static final String VCI_BASE_PATH = "/vci/v1";

    // VCI API Endpoints
    public static final String VCI_PATH = VCI_BASE_PATH+"/**";

    // Issuance Endpoint (unified)
    public static final String ISSUANCES_PATH = "/api/v1/issuances";
    public static final String ISSUANCES_WILDCARD_PATH = "/api/v1/issuances/**";

    // Authenticated user info (role + org for the current tenant)
    public static final String ME_PATH = "/api/v1/me";

    // Tenant credential catalog admin (EUD-72, US-02). Tenant admin GET/PUT of the
    // per-tenant enabled credential configuration ids.
    public static final String CREDENTIAL_CATALOG_PATH = "/admin/v1/credential-catalog";

    // Unattended issuance intake (EUD-2/EUD-75, US-02). Path is a placeholder
    // pending EUD-74 (US-01, the intake endpoint itself) — coordinate before
    // changing, since it is a stable contract shared with that Story.
    public static final String INTAKE_BASE_PATH = "/api/v1/intake";
    public static final String INTAKE_PATH = INTAKE_BASE_PATH + "/**";

    // OIDC4VCI Endpoints
    public static final String CORS_OID4VCI_PATH = "/oid4vci/**";
    public static final String OID4VCI_CREDENTIAL_OFFER_PATH = OID4VCI_BASE_PATH + "/credential-offer";
    public static final String OID4VCI_CREDENTIAL_PATH = OID4VCI_BASE_PATH + "/credential";
    public static final String OID4VCI_DEFERRED_CREDENTIAL_PATH = OID4VCI_BASE_PATH + "/deferred-credential";
    public static final String OID4VCI_NOTIFICATION_PATH = OID4VCI_BASE_PATH + "/notification";

    public static final String CORS_CREDENTIAL_OFFER_PATH = OID4VCI_BASE_PATH + "/credential-offer/**";

    // Well-Known Endpoints
    public static final String WELL_KNOWN_PATH = WELL_KNOWN_BASE_PATH + "/**";
    public static final String CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH = WELL_KNOWN_BASE_PATH + "/openid-credential-issuer";
    public static final String AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH = WELL_KNOWN_BASE_PATH + "/openid-configuration";
    public static final String OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH = WELL_KNOWN_BASE_PATH + "/oauth-authorization-server";
    public static final String JWKS_PATH = WELL_KNOWN_BASE_PATH + "/jwks.json";

    // Well-Known Endpoints (RFC 8414 / OID4VCI 1.0 §12.2.2 form: well-known
    // inserted before the issuer's own path, e.g. /.well-known/openid-credential-issuer/issuer).
    // A compliant client derives this from our credential_issuer identifier
    // (which has a path, "/issuer") — see EUD-215.
    public static final String CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_WILDCARD_PATH = CREDENTIAL_ISSUER_METADATA_WELL_KNOWN_PATH + "/**";
    public static final String AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_WILDCARD_PATH = AUTHORIZATION_SERVER_METADATA_WELL_KNOWN_PATH + "/**";
    public static final String OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_WILDCARD_PATH = OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH + "/**";

    // Authorization Code Flow Endpoints
    public static final String OID4VCI_PAR_PATH = OID4VCI_BASE_PATH + "/par";
    public static final String OID4VCI_AUTHORIZE_PATH = OID4VCI_BASE_PATH + "/authorize";
    public static final String OID4VCI_NONCE_PATH = OID4VCI_BASE_PATH + "/nonce";

    // oauth Endpoints
    public static final String OAUTH_PATH ="/oauth/**";
    public static final String OAUTH_TOKEN_PATH = "/oauth/token";

    // Issuance Endpoints
    public static final String ISSUANCE_PATH = "/issuance/**";
    public static final String ISSUANCE_STATUS_CREDENTIALS = ISSUANCE_BASE_PATH+"/credentials/status/**";
    public static final String ISSUANCE_RETRY_SIGN_CREDENTIALS = ISSUANCE_BASE_PATH+"/retry-sign-credential/{id}";
    public static final String ISSUANCE_DEFERRED_CREDENTIALS = ISSUANCE_BASE_PATH + "/deferred-credentials";

    // Bootstrap Endpoint
    public static final String BOOTSTRAP_PATH = "/api/v1/bootstrap";

    // Credential Offer Refresh
    public static final String CREDENTIAL_OFFER_REFRESH_PATH = "/credential-offer/refresh/**";

    //status list Endpoints
    public static final String STATUS_LIST_BASE = "/w3c/v1/credentials/status";
    public static final String STATUS_LIST_PATH = STATUS_LIST_BASE + "/**";
    public static final String TOKEN_STATUS_LIST_BASE = "/token/v1/credentials/status";
    public static final String TOKEN_STATUS_LIST_PATH = TOKEN_STATUS_LIST_BASE + "/**";

}
