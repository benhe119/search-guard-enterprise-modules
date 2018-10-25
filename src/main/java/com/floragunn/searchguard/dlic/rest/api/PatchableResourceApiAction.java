/*
 * Copyright 2016-2018 by floragunn GmbH - All rights reserved
 * 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * This software is free of charge for non-commercial and academic use. 
 * For commercial use in a production environment you have to obtain a license 
 * from https://floragunn.com
 * 
 */

package com.floragunn.searchguard.dlic.rest.api;

import java.nio.file.Path;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flipkart.zjsonpatch.JsonPatch;
import com.flipkart.zjsonpatch.JsonPatchApplicationException;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;
import com.floragunn.searchguard.dlic.rest.support.Utils;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;

public abstract class PatchableResourceApiAction extends AbstractApiAction {

    private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    protected final Logger log = LogManager.getLogger(this.getClass());

    public PatchableResourceApiAction(Settings settings, Path configPath, RestController controller, Client client,
            AdminDNs adminDNs, IndexBaseConfigurationRepository cl, ClusterService cs,
            PrincipalExtractor principalExtractor, PrivilegesEvaluator evaluator, ThreadPool threadPool,
            AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
                auditLog);
    }

    protected Tuple<String[], RestResponse> handlePatch(final RestRequest request, final Client client)
            throws Throwable {
        if (request.getXContentType() != XContentType.JSON) {
            return badRequestResponse("PATCH accepts only application/json");
        }

        String name = request.param("name");
        Settings existingAsSettings = loadAsSettings(getConfigName(), false);

        JsonNode jsonPatch;

        try {
            jsonPatch = OBJECT_MAPPER.readTree(request.content().utf8ToString());
        } catch (JsonParseException e) {
            log.debug("Error while parsing JSON patch", e);
            return badRequestResponse("Error in JSON patch: " + e.getMessage());
        }

        JsonNode existingAsJsonNode = Utils.convertJsonToJackson(existingAsSettings);

        if (!(existingAsJsonNode instanceof ObjectNode)) {
            return internalErrorResponse("Config " + getConfigName() + " is malformed");
        }

        ObjectNode existingAsObjectNode = (ObjectNode) existingAsJsonNode;

        if (Strings.isNullOrEmpty(name)) {
            return handleBulkPatch(request, client, existingAsSettings, existingAsObjectNode, jsonPatch);
        } else {
            return handleSinglePatch(request, client, name, existingAsSettings, existingAsObjectNode, jsonPatch);
        }
    }

    protected Tuple<String[], RestResponse> handleSinglePatch(RestRequest request, Client client, String name,
            Settings existingAsSettings, ObjectNode existingAsObjectNode, JsonNode jsonPatch) throws Throwable {
        if (isHidden(existingAsSettings, name)) {
            return notFound(getResourceName() + " " + name + " not found.");
        }

        if (isReadOnly(existingAsSettings, name)) {
            return forbidden("Resource '" + name + "' is read-only.");
        }

        Settings resourceSettings = existingAsSettings.getAsSettings(name);

        if (resourceSettings.isEmpty()) {
            return notFound(getResourceName() + " " + name + " not found.");
        }

        JsonNode existingResourceAsJsonNode = existingAsObjectNode.get(name);

        JsonNode patchedResourceAsJsonNode;

        try {
            patchedResourceAsJsonNode = applyPatch(jsonPatch, existingResourceAsJsonNode);
        } catch (JsonPatchApplicationException e) {
            log.debug("Error while applying JSON patch", e);
            return badRequestResponse(e.getMessage());
        }
        
        postProcessApplyPatchResult(existingResourceAsJsonNode, patchedResourceAsJsonNode);

        AbstractConfigurationValidator validator = getValidator(request.method(), patchedResourceAsJsonNode);

        if (!validator.validateSettings()) {
            request.params().clear();
            return new Tuple<String[], RestResponse>(new String[0],
                    new BytesRestResponse(RestStatus.BAD_REQUEST, validator.errorsAsXContent()));
        }

        JsonNode updatedAsJsonNode = existingAsObjectNode.deepCopy().set(name, patchedResourceAsJsonNode);

        BytesReference updatedAsBytesReference = new BytesArray(
                OBJECT_MAPPER.writeValueAsString(updatedAsJsonNode).getBytes());

        save(client, request, getConfigName(), updatedAsBytesReference);

        return successResponse("'" + name + "' updated.", getConfigName());
    }

    protected Tuple<String[], RestResponse> handleBulkPatch(RestRequest request, Client client,
            Settings existingAsSettings, ObjectNode existingAsObjectNode, JsonNode jsonPatch) throws Throwable {

        JsonNode patchedAsJsonNode;

        try {
            patchedAsJsonNode = applyBulkPatch(jsonPatch, existingAsObjectNode);
        } catch (JsonPatchApplicationException e) {
            log.debug("Error while applying JSON patch", e);            
            return badRequestResponse(e.getMessage());
        }

        for (String resourceName : existingAsSettings.names()) {
            JsonNode oldResource = existingAsObjectNode.get(resourceName);
            JsonNode patchedResource = patchedAsJsonNode.get(resourceName);

            if (oldResource != null && !oldResource.equals(patchedResource)) {

                if (isReadOnly(existingAsSettings, resourceName)) {
                    return forbidden("Resource '" + resourceName + "' is read-only.");
                }

                if (isHidden(existingAsSettings, resourceName)) {
                    return badRequestResponse("Resource name '" + resourceName + "' is reserved");
                }
            }
        }

        for (Iterator<String> fieldNamesIter = patchedAsJsonNode.fieldNames(); fieldNamesIter.hasNext();) {
            String resourceName = fieldNamesIter.next();

            JsonNode oldResource = existingAsObjectNode.get(resourceName);
            JsonNode patchedResource = patchedAsJsonNode.get(resourceName);
            
            postProcessApplyPatchResult(oldResource, patchedResource);

            if (oldResource == null || !oldResource.equals(patchedResource)) {
                AbstractConfigurationValidator validator = getValidator(request.method(), patchedResource);

                if (!validator.validateSettings()) {
                    request.params().clear();
                    return new Tuple<String[], RestResponse>(new String[0],
                            new BytesRestResponse(RestStatus.BAD_REQUEST, validator.errorsAsXContent()));
                }
            }
        }

        BytesReference updatedAsBytesReference = new BytesArray(
                OBJECT_MAPPER.writeValueAsString(patchedAsJsonNode).getBytes());

        save(client, request, getConfigName(), updatedAsBytesReference);

        return successResponse("Resource updated.", getConfigName());
    }

    protected JsonNode applyPatch(JsonNode jsonPatch, JsonNode existingResourceAsJsonNode) {
        return JsonPatch.apply(jsonPatch, existingResourceAsJsonNode);
    }

    protected JsonNode applyBulkPatch(JsonNode jsonPatch, JsonNode existingObjectAsJsonNode) {
        return JsonPatch.apply(jsonPatch, existingObjectAsJsonNode);
    }
    
    protected void postProcessApplyPatchResult(JsonNode existingResourceAsJsonNode, JsonNode updatedResourceAsJsonNode) {
        // do nothing by default
    }
    
    protected Tuple<String[], RestResponse> handleApiRequest(final RestRequest request, final Client client)
            throws Throwable {

        if (request.method() == Method.PATCH) {
            return handlePatch(request, client);
        } else {
            return super.handleApiRequest(request, client);
        }
    }

    protected AbstractConfigurationValidator getValidator(RestRequest.Method method, JsonNode patchedResource)
            throws JsonProcessingException {
        BytesReference patchedResourceAsByteReference = new BytesArray(
                OBJECT_MAPPER.writeValueAsString(patchedResource).getBytes());

        return getValidator(method, patchedResourceAsByteReference);
    }
}
