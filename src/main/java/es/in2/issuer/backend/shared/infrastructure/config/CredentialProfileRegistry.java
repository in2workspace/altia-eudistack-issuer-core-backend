package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfileBindingInvariant;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class CredentialProfileRegistry implements CredentialProfileCatalog {

    private final Map<String, CredentialProfile> byConfigurationId;
    private final Map<String, CredentialProfile> byCredentialType;
    private final Map<String, JsonNode> rawProfilesByConfigurationId;

    public CredentialProfileRegistry(
            ObjectMapper objectMapper,
            ResourcePatternResolver resourcePatternResolver,
            @Value("${credential.profiles.path:classpath:credentials/profiles}") String profilesBasePath) {
        String profilesPattern = profilesBasePath + "/**/*.json";
        Map<String, CredentialProfile> configIdMap = new LinkedHashMap<>();
        Map<String, CredentialProfile> typeMap = new LinkedHashMap<>();
        Map<String, JsonNode> rawMap = new LinkedHashMap<>();

        try {
            Resource[] resources = resourcePatternResolver.getResources(profilesPattern);

            List<Resource> coreResources = new ArrayList<>();
            Map<String, JsonNode> profileOverrides = new LinkedHashMap<>();

            for (Resource resource : resources) {
                String filename = resource.getFilename();
                if (filename != null && filename.matches(".*\\.sample.*\\.json")) {
                    log.debug("Skipping sample credential profile file {}", filename);
                    continue;
                }
                if (filename != null && filename.endsWith(".profile.json")) {
                    JsonNode profileJson = readJsonResource(objectMapper, resource);
                    String configId = extractConfigurationId(profileJson, filename);
                    profileOverrides.put(configId, profileJson);
                    log.debug("Loaded profile overlay '{}' from {}", configId, filename);
                } else {
                    coreResources.add(resource);
                }
            }

            for (Resource resource : coreResources) {
                loadCoreWithOptionalProfile(objectMapper, resource, profileOverrides, configIdMap, typeMap, rawMap);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load credential profiles from " + profilesPattern, e);
        }

        if (configIdMap.isEmpty()) {
            log.warn("No credential profiles found at {}", profilesPattern);
        } else {
            log.info("Loaded {} credential profile(s): {}", configIdMap.size(), configIdMap.keySet());
        }

        this.byConfigurationId = Collections.unmodifiableMap(configIdMap);
        this.byCredentialType = Collections.unmodifiableMap(typeMap);
        this.rawProfilesByConfigurationId = Collections.unmodifiableMap(rawMap);
    }

    private JsonNode readJsonResource(ObjectMapper objectMapper, Resource resource) {
        String filename = resource.getFilename();
        try (InputStream is = resource.getInputStream()) {
            return objectMapper.readTree(is);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse JSON from " + filename, e);
        }
    }

    private String extractConfigurationId(JsonNode json, String filename) {
        JsonNode idNode = json.get("credential_configuration_id");
        if (idNode == null || idNode.asText().isBlank()) {
            throw new IllegalStateException(
                    "Profile in " + filename + " has no credential_configuration_id");
        }
        return idNode.asText();
    }

    private void loadCoreWithOptionalProfile(ObjectMapper objectMapper, Resource resource,
                                             Map<String, JsonNode> profileOverrides,
                                             Map<String, CredentialProfile> configIdMap,
                                             Map<String, CredentialProfile> typeMap,
                                             Map<String, JsonNode> rawMap) {
        String filename = resource.getFilename();
        JsonNode coreJson = readJsonResource(objectMapper, resource);
        String configId = extractConfigurationId(coreJson, filename);

        JsonNode profileOverlay = profileOverrides.get(configId);
        JsonNode mergedJson;
        if (profileOverlay != null) {
            ((ObjectNode) coreJson).setAll((ObjectNode) profileOverlay);
            mergedJson = coreJson;
            log.debug("Merged profile overlay onto core '{}' from {}", configId, filename);
        } else {
            mergedJson = coreJson;
        }

        try {
            CredentialProfile profile = objectMapper.treeToValue(mergedJson, CredentialProfile.class);

            if (configIdMap.containsKey(configId)) {
                throw new IllegalStateException(
                        "Duplicate credential_configuration_id '" + configId + "' in " + filename);
            }

            // Fail-fast at the loading boundary (ADR-110): a profile whose three binding fields
            // contradict one another used to surface as a 500 on its first issuance. Now it stops
            // the service from starting, naming the profile and the offending field.
            CredentialProfileBindingInvariant.validate(profile);

            String credentialType = profile.credentialType();
            if (typeMap.containsKey(credentialType)) {
                log.warn("Multiple profiles share credential type '{}' (skipping typeMap entry for '{}'). " +
                        "Use getByConfigurationId() for unambiguous lookup.", credentialType, configId);
            } else {
                typeMap.put(credentialType, profile);
            }

            configIdMap.put(configId, profile);
            rawMap.put(configId, mergedJson);

            log.info("Loaded credential profile '{}' (type: {}) from {}", configId, credentialType, filename);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse credential profile from " + filename, e);
        }
    }

    @Override
    public CredentialProfile getByConfigurationId(String credentialConfigurationId) {
        return byConfigurationId.get(credentialConfigurationId);
    }

    public CredentialProfile getByCredentialType(String credentialType) {
        return byCredentialType.get(credentialType);
    }

    /**
     * Resolves a profile from an identifier that may be either a {@code credential_configuration_id}
     * or a bare W3C credential type name.
     *
     * <p>Modern profiles encode the configuration id inside {@code credential_definition.type},
     * so both indexes coincide. Legacy DOME credentials carry a human-readable type instead
     * (e.g. {@code LEARCredentialEmployee}), which only exists in the credential-type index.
     *
     * @return the matching profile, or {@code null} when neither index contains the key
     */
    public CredentialProfile resolveProfile(String credentialTypeOrConfigurationId) {
        CredentialProfile profile = byConfigurationId.get(credentialTypeOrConfigurationId);
        return profile != null ? profile : byCredentialType.get(credentialTypeOrConfigurationId);
    }

    public Map<String, CredentialProfile> getAllProfiles() {
        return byConfigurationId;
    }

    public JsonNode getRawProfile(String credentialConfigurationId) {
        return rawProfilesByConfigurationId.get(credentialConfigurationId);
    }
}
