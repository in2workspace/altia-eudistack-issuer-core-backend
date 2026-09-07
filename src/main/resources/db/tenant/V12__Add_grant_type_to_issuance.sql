-- Dedalo-1052543: persist OID4VCI grant used at issuance so credential-offer refresh
-- regenerates the same grant (pre-authorized vs authorization_code).
ALTER TABLE issuance
    ADD COLUMN IF NOT EXISTS grant_type VARCHAR(128);

UPDATE issuance
   SET grant_type = 'authorization_code'
 WHERE grant_type IS NULL;

ALTER TABLE issuance
    ALTER COLUMN grant_type SET DEFAULT 'authorization_code',
    ALTER COLUMN grant_type SET NOT NULL;
