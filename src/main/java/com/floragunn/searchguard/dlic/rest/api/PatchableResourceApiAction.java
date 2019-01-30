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
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flipkart.zjsonpatch.JsonPatch;
import com.flipkart.zjsonpatch.JsonPatchApplicationException;
import com.floragunn.searchguard.DefaultObjectMapper;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.dlic.rest.support.Utils;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.privileges.PrivilegesEvaluator;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;

public abstract class PatchableResourceApiAction extends AbstractApiAction {

    protected final Logger log = LogManager.getLogger(this.getClass());

    public PatchableResourceApiAction(Settings settings, Path configPath, RestController controller, Client client,
            AdminDNs adminDNs, IndexBaseConfigurationRepository cl, ClusterService cs,
            PrincipalExtractor principalExtractor, PrivilegesEvaluator evaluator, ThreadPool threadPool,
            AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
                auditLog);
    }

    private Tuple<String[], RestResponse> handlePatch(RestChannel channel, final RestRequest request, final Client client)
            throws Throwable {
        if (request.getXContentType() != XContentType.JSON) {
            return badRequestResponse(channel, "PATCH accepts only application/json");
        }

        String name = request.param("name");
        Settings existingAsSettings = loadAsSettings(getConfigName(), false);

        JsonNode jsonPatch;

        try {
            jsonPatch = DefaultObjectMapper.objectMapper.readTree(request.content().utf8ToString());
        } catch (JsonParseException e) {
            log.debug("Error while parsing JSON patch", e);
            return badRequestResponse(channel, "Error in JSON patch: " + e.getMessage());
        }

        JsonNode existingAsJsonNode = Utils.convertJsonToJackson(existingAsSettings);

        if (!(existingAsJsonNode instanceof ObjectNode)) {
            return internalErrorResponse(channel, "Config " + getConfigName() + " is malformed");
        }

        ObjectNode existingAsObjectNode = (ObjectNode) existingAsJsonNode;

        if (Strings.isNullOrEmpty(name)) {
            return handleBulkPatch(channel, request, client, existingAsSettings, existingAsObjectNode, jsonPatch);
        } else {
            return handleSinglePatch(channel, request, client, name, existingAsSettings, existingAsObjectNode, jsonPatch);
        }
    }

    private Tuple<String[], RestResponse> handleSinglePatch(RestChannel channel, RestRequest request, Client client, String name,
            Settings existingAsSettings, ObjectNode existingAsObjectNode, JsonNode jsonPatch) throws Throwable {
        if (isHidden(existingAsSettings, name)) {
            return notFound(channel, getResourceName() + " " + name + " not found.");
        }

        if (isReadOnly(existingAsSettings, name)) {
            return forbidden(channel, "Resource '" + name + "' is read-only.");
        }

        Settings resourceSettings = existingAsSettings.getAsSettings(name);

        if (resourceSettings.isEmpty()) {
            return notFound(channel, getResourceName() + " " + name + " not found.");
        }

        JsonNode existingResourceAsJsonNode = existingAsObjectNode.get(name);

        JsonNode patchedResourceAsJsonNode;

        try {
            patchedResourceAsJsonNode = applyPatch(jsonPatch, existingResourceAsJsonNode);
        } catch (JsonPatchApplicationException e) {
            log.debug("Error while applying JSON patch", e);
            return badRequestResponse(channel, e.getMessage());
        }
                
        AbstractConfigurationValidator originalValidator = postProcessApplyPatchResult(channel, request, existingResourceAsJsonNode, patchedResourceAsJsonNode, name);

        if(originalValidator != null) {
        	if (!originalValidator.validateSettings()) {
                request.params().clear();
                return new Tuple<String[], RestResponse>(new String[0],
                        new BytesRestResponse(RestStatus.BAD_REQUEST, originalValidator.errorsAsXContent(channel)));
            }
        }
        
        AbstractConfigurationValidator validator = getValidator(request, patchedResourceAsJsonNode);

        if (!validator.validateSettings()) {
            request.params().clear();
            return new Tuple<String[], RestResponse>(new String[0],
                    new BytesRestResponse(RestStatus.BAD_REQUEST, validator.errorsAsXContent(channel)));
        }

        JsonNode updatedAsJsonNode = existingAsObjectNode.deepCopy().set(name, patchedResourceAsJsonNode);

        BytesReference updatedAsBytesReference = new BytesArray(
                DefaultObjectMapper.objectMapper.writeValueAsString(updatedAsJsonNode).getBytes());

        save(client, request, getConfigName(), updatedAsBytesReference);

        return successResponse(channel, "'" + name + "' updated.", getConfigName());
    }

    private Tuple<String[], RestResponse> handleBulkPatch(RestChannel channel, RestRequest request, Client client,
            Settings existingAsSettings, ObjectNode existingAsObjectNode, JsonNode jsonPatch) throws Throwable {

        JsonNode patchedAsJsonNode;

        try {
            patchedAsJsonNode = applyPatch(jsonPatch, existingAsObjectNode);
        } catch (JsonPatchApplicationException e) {
            log.debug("Error while applying JSON patch", e);
            return badRequestResponse(channel, e.getMessage());
        }

        for (String resourceName : existingAsSettings.names()) {
            JsonNode oldResource = existingAsObjectNode.get(resourceName);
            JsonNode patchedResource = patchedAsJsonNode.get(resourceName);

            if (oldResource != null && !oldResource.equals(patchedResource)) {

                if (isReadOnly(existingAsSettings, resourceName)) {
                    return forbidden(channel, "Resource '" + resourceName + "' is read-only.");
                }

                if (isHidden(existingAsSettings, resourceName)) {
                    return badRequestResponse(channel, "Resource name '" + resourceName + "' is reserved");
                }
            }
        }

        for (Iterator<String> fieldNamesIter = patchedAsJsonNode.fieldNames(); fieldNamesIter.hasNext();) {
            String resourceName = fieldNamesIter.next();

            JsonNode oldResource = existingAsObjectNode.get(resourceName);
            JsonNode patchedResource = patchedAsJsonNode.get(resourceName);
                        
            AbstractConfigurationValidator originalValidator = postProcessApplyPatchResult(channel, request, oldResource, patchedResource, resourceName);
            
            if(originalValidator != null) {
            	if (!originalValidator.validateSettings()) {
                    request.params().clear();
                    return new Tuple<String[], RestResponse>(new String[0],
                            new BytesRestResponse(RestStatus.BAD_REQUEST, originalValidator.errorsAsXContent(channel)));
                }
            }

            if (oldResource == null || !oldResource.equals(patchedResource)) {
                AbstractConfigurationValidator validator = getValidator(request, patchedResource);

                if (!validator.validateSettings()) {
                    request.params().clear();
                    return new Tuple<String[], RestResponse>(new String[0],
                            new BytesRestResponse(RestStatus.BAD_REQUEST, validator.errorsAsXContent(channel)));
                }
            }
        }

        BytesReference updatedAsBytesReference = new BytesArray(
                DefaultObjectMapper.objectMapper.writeValueAsString(patchedAsJsonNode).getBytes());

        save(client, request, getConfigName(), updatedAsBytesReference);

        return successResponse(channel, "Resource updated.", getConfigName());
    }

    private JsonNode applyPatch(JsonNode jsonPatch, JsonNode existingResourceAsJsonNode) {
        return JsonPatch.apply(jsonPatch, existingResourceAsJsonNode);
    }

    protected AbstractConfigurationValidator postProcessApplyPatchResult(RestChannel channel, RestRequest request, JsonNode existingResourceAsJsonNode, JsonNode updatedResourceAsJsonNode, String resourceName) {
        // do nothing by default
    	return null;
    }
    
    @Override
    protected Tuple<String[], RestResponse> handleApiRequest(RestChannel channel, final RestRequest request, final Client client)
            throws Throwable {

        if (request.method() == Method.PATCH) {
            return handlePatch(channel, request, client);
        } else {
            return super.handleApiRequest(channel, request, client);
        }
    }

    private AbstractConfigurationValidator getValidator(RestRequest request, JsonNode patchedResource)
            throws JsonProcessingException {
        BytesReference patchedResourceAsByteReference = new BytesArray(
                DefaultObjectMapper.objectMapper.writeValueAsString(patchedResource).getBytes());
        return getValidator(request, patchedResourceAsByteReference);
    }
}
