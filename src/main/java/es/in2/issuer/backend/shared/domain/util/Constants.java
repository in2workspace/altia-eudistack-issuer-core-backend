package es.in2.issuer.backend.shared.domain.util;

import java.util.concurrent.TimeUnit;

public final class Constants {

    private Constants() {
        throw new IllegalStateException("Utility class");
    }

    // CREDENTIAL TYPES
    public static final String VERIFIABLE_CREDENTIAL = "VerifiableCredential";
    public static final String VERIFIABLE_ATTESTATION = "VerifiableAttestation";

    // CREDENTIAL FORMATS
    public static final String JWT_VC_JSON = "jwt_vc_json";
    public static final String DC_SD_JWT = "dc+sd-jwt";
    public static final String CWT_VC = "cwt_vc";
    public static final String VC = "vc";

    // JWT TYPE HEADERS
    public static final String VC_JWT_TYP = "vc+jwt";

    // CREDENTIAL CONTEXTS
    public static final String CREDENTIALS_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";

    // OIDC4VCI
    public static final String CREDENTIAL_OFFER_PREFIX = "openid-credential-offer://?credential_offer_uri=";
    public static final String CREDENTIAL_OFFER_URI_PARAMETER = "credential_offer_uri";
    public static final String WALLET_PROTOCOL_CALLBACK = "/protocol/callback";

    // CREDENTIAL JSON FIELDS
    public static final String CREDENTIAL_SUBJECT = "credentialSubject";
    public static final String MANDATE = "mandate";
    public static final String MANDATOR = "mandator";
    public static final String ORGANIZATION = "organization";
    public static final String ORGANIZATION_IDENTIFIER = "organizationIdentifier";
    public static final String TYPE = "type";
    public static final String CREDENTIAL_STATUS = "credentialStatus";
    public static final String STATUS_LIST_CREDENTIAL = "statusListCredential";
    public static final String ISSUER = "issuer";
    public static final String VALID_FROM = "validFrom";
    public static final String ISSUANCE_DATE = "issuanceDate";
    public static final String EXPIRATION_DATE = "expirationDate";
    public static final String ID = "id";
    public static final String SIGNER = "signer";
    public static final String COMPANY = "company";
    public static final String PRODUCT = "product";
    public static final String PRODUCT_ID = "productId";
    public static final String PRODUCT_NAME = "productName";

    // PERSON FIELDS
    public static final String EMAIL = "email";
    public static final String FIRST_NAME = "firstName";
    public static final String LAST_NAME = "lastName";

    // DID PREFIXES
    public static final String DID_ELSI = "did:elsi:";

    // GRANT TYPES
    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    public static final String REFRESH_TOKEN_GRANT_TYPE = "refresh_token";
    public static final String PRE_AUTHORIZED_CODE = "pre-authorized_code";
    public static final String AUTHORIZATION_CODE = "authorization_code";

    // HTTP
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String UTF_8 = "UTF-8";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String CONTENT_TYPE_APPLICATION_JSON = "application/json";
    public static final String CONTENT_TYPE_URL_ENCODED_FORM = "application/x-www-form-urlencoded";
    public static final String OPTIONS = "OPTIONS";

    // PROOF VALIDATION
    public static final String SUPPORTED_PROOF_ALG = "ES256";
    public static final String SUPPORTED_PROOF_TYP = "openid4vci-proof+jwt";

    // EXPIRATION TIMES
    public static final Integer CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME = 10;
    public static final Integer VERIFIABLE_CREDENTIAL_JWT_CACHE_EXPIRATION_TIME = 10;
    // SEC-02: Refresh token — 24 hours (was 30 days)
    public static final long REFRESH_TOKEN_EXPIRATION = 24;
    public static final TimeUnit REFRESH_TOKEN_EXPIRATION_TIME_UNIT = TimeUnit.HOURS;
    public static final long PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES = 10;
    public static final Long DEFERRED_CREDENTIAL_POLLING_INTERVAL = 3600L;

    // REMOTE SIGNATURE
    public static final String SIGNATURE_REMOTE_TYPE_CLOUD = "cloud";
    public static final String SIGNATURE_REMOTE_SCOPE_SERVICE = "service";
    public static final String SIGNATURE_REMOTE_SCOPE_CREDENTIAL = "credential";
    public static final String CREDENTIAL_ID = "credentialID";
    public static final String NUM_SIGNATURES = "numSignatures";
    public static final String AUTH_DATA = "authData";
    public static final String AUTH_DATA_ID = "id";
    public static final String AUTH_DATA_VALUE = "value";

    // BITSTRING ENCODING
    public static final long MSB = 0x80L;
    public static final long MSBALL = 0xFFFFFF80L;

    // CREDENTIAL DESCRIPTIONS
    public static final String DEFAULT_USER_NAME = "Cloud Provider";
    public static final String ENGLISH = "en";

    // EMAIL
    public static final String CREDENTIAL_ACTIVATION_EMAIL_SUBJECT = "email.activation.subject";
    public static final String CREDENTIAL_READY = "email.credential-ready";

    // ERROR MESSAGES
    public static final String REQUEST_ERROR_MESSAGE = "Error processing the request";
    public static final String PARSING_CREDENTIAL_ERROR_MESSAGE = "Error parsing credential";
    public static final String MAIL_ERROR_COMMUNICATION_EXCEPTION_MESSAGE = "Error during communication with the mail server";
    public static final String AUTHENTICATION_FAILED = "Authentication failed";
    public static final String ERROR_LOG_FORMAT = "[Error Instance ID: {}] Path: {}, Status: {}, Title: {}, Message: {}";

    // MULTI-TENANCY
    public static final String X_TENANT_HEADER = "X-Tenant";
    public static final String TENANT_DOMAIN_CONTEXT_KEY = "tenantDomain";
    public static final String PLATFORM_TENANT = "platform";
    // Sentinel used when no tenant is present in the Reactor Context (system operations,
    // schedulers, misrouted requests). Mirrors TenantAwareConnectionFactoryDecorator's
    // fallback, which resolves this to search_path=public — keep any other tenant-context
    // default aligned with this value so audit/log output matches the schema actually used.
    public static final String SYSTEM_TENANT = "*";
    // Service-specific suffix appended to the tenant id to resolve the PostgreSQL schema
    // (e.g. tenant "sandbox" -> schema "sandbox_issuer"). Prevents flyway_schema_history
    // collisions when multiple services share the same database.
    public static final String SCHEMA_SUFFIX = "_issuer";
}
