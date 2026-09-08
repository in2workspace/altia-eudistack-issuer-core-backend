-- =============================================================================
-- V13__Add_delivery_modes_to_tenant_credential_profile.sql
-- EUD-169: delivery modes become a column of the tenant's credential catalog
-- (tenant_credential_profile), replacing the parallel tenant_config-based
-- module (issuer.delivery.modes.* keys). Additive, idempotent, fail-closed.
-- (V12 was already taken by EUD-168, hence V13.)
-- =============================================================================

-- 1) Columna aditiva, idempotente (patrón de V9/V11)
ALTER TABLE tenant_credential_profile
    ADD COLUMN IF NOT EXISTS delivery_modes VARCHAR(64);

-- 2) GUARDA fail-closed (ES-08): configuración previa que NO puede trasladarse
--    sin ampliar permisos en silencio.
DO $$
DECLARE unmigratable int;
BEGIN
    SELECT count(*) INTO unmigratable
      FROM tenant_config c
     WHERE c.config_key LIKE 'issuer.delivery.modes.%'
       AND (
            -- (a) valor no interpretable
            c.config_value !~ '^(direct|email|ui)(,(direct|email|ui))*$'
            -- (b) catálogo vacío ⇒ "vacío = todo habilitado": no hay fila donde
            --     aterrizar y crear una invertiría la semántica del catálogo
         OR NOT EXISTS (SELECT 1 FROM tenant_credential_profile)
       );
    IF unmigratable > 0 THEN
        RAISE EXCEPTION
          'EUD-169: % delivery-mode key(s) cannot be migrated losslessly in schema %. Resolve before deploying.',
          unmigratable, current_schema();
    END IF;
END $$;

-- 3) Backfill idempotente (EC-06). Las claves cuyo ccid no está habilitado
--    se ignoran deliberadamente: el tipo no es emisible en ese tenant (EC-07).
UPDATE tenant_credential_profile p
   SET delivery_modes = c.config_value,
       updated_at     = now()
  FROM tenant_config c
 WHERE c.config_key = 'issuer.delivery.modes.' || p.credential_configuration_id
   AND p.delivery_modes IS NULL;

-- 3b) EC-07 "queda registrado para poder auditarlo": la fila de tenant_config no se
--     borra (red de seguridad del rollback), pero además se deja constancia explícita
--     en el log de despliegue de qué claves no aterrizaron por no tener fila habilitada.
DO $$
DECLARE discarded text;
BEGIN
    SELECT string_agg(c.config_key, ', ') INTO discarded
      FROM tenant_config c
     WHERE c.config_key LIKE 'issuer.delivery.modes.%'
       AND NOT EXISTS (
           SELECT 1 FROM tenant_credential_profile p
            WHERE p.credential_configuration_id = substring(c.config_key FROM length('issuer.delivery.modes.') + 1)
       );
    IF discarded IS NOT NULL THEN
        RAISE NOTICE
          'EUD-169: discarded legacy delivery-mode key(s) for not-enabled credential_configuration_id(s) in schema %: %',
          current_schema(), discarded;
    END IF;
END $$;

-- 4) Invariante de forma a nivel de datos, tras el backfill
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'chk_tcp_delivery_modes'
                      AND conrelid = 'tenant_credential_profile'::regclass) THEN
        ALTER TABLE tenant_credential_profile
            ADD CONSTRAINT chk_tcp_delivery_modes
            CHECK (delivery_modes IS NULL
                   OR delivery_modes ~ '^(direct|email|ui)(,(direct|email|ui))*$');
    END IF;
END $$;
