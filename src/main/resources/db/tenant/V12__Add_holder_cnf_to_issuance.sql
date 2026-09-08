-- =============================================================================
-- V12__Add_holder_cnf_to_issuance.sql
-- EUD-168 (AD-8): the machine LEARCredential types keep a cnf claim while declaring no
-- proof_types_supported, so their holder key arrives once -- in the body of
-- POST /api/v1/issuances -- and is needed again later, at the OID4VCI Credential Endpoint,
-- where no key proof will ever arrive to replace it. The wallet delivery modes sign in a
-- separate request from the one that carries the key, so the key has to outlive it:
-- an in-memory cache would not survive a restart, nor be visible to the ECS task that
-- happens to serve the Credential Request.
--
-- Nullable by design: only the types exempt from ADR-110 populate it. Holds the cnf claim
-- as JSON exactly as it will be written into the credential ({"jwk": ...}) -- public key
-- material, never a secret. Only the jwk member is ever accepted (HolderKey.fromJson);
-- kid/x5c were considered and dropped (D3, F1a) since they can never be verified on this
-- path.
-- =============================================================================
ALTER TABLE issuance
    ADD COLUMN IF NOT EXISTS holder_cnf TEXT;
