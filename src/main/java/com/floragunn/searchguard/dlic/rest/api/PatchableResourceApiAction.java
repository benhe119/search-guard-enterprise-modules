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

import java.io.IOException;
import java.nio.file.Path;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.index.IndexResponse;
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
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

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

    private void handlePatch(RestChannel channel, final RestRequest request, final Client client)
            throws IOException  {
        if (request.getXContentType() != XContentType.JSON) {
            badRequestResponse(channel, "PATCH accepts only application/json");
            return;
        }

        String name = request.param("name");
        Tuple<Long, Settings> existingAsSettings = loadAsSettings(getConfigName(), false);

        JsonNode jsonPatch;

        try {
            jsonPatch = DefaultObjectMapper.objectMapper.readTree(request.content().utf8ToString());
        } catch (IOException e) {
            log.debug("Error while parsing JSON patch", e);
            badRequestResponse(channel, "Error in JSON patch: " + e.getMessage());
            return;
        }

        JsonNode existingAsJsonNode = Utils.convertJsonToJackson(existingAsSettings.v2());

        if (!(existingAsJsonNode instanceof ObjectNode)) {
            internalErrorResponse(channel, "Config " + getConfigName() + " is malformed");
            return;
        }

        ObjectNode existingAsObjectNode = (ObjectNode) existingAsJsonNode;

        if (Strings.isNullOrEmpty(name)) {
            handleBulkPatch(channel, request, client, existingAsSettings, existingAsObjectNode, jsonPatch);
        } else {
            handleSinglePatch(channel, request, client, name, existingAsSettings, existingAsObjectNode, jsonPatch);
        }
    }

    private void handleSinglePatch(RestChannel channel, RestRequest request, Client client, String name,
            Tuple<Long,Settings> existingAsSettings, ObjectNode existingAsObjectNode, JsonNode jsonPatch) throws IOException {
        if (isHidden(existingAsSettings.v2(), name)) {
            notFound(channel, getResourceName() + " " + name + " not found.");
            return;
        }

        if (isReadOnly(existingAsSettings.v2(), name)) {
            forbidden(channel, "Resource '" + name + "' is read-only.");
            return;
        }

        Settings resourceSettings = existingAsSettings.v2().getAsSettings(name);

        if (resourceSettings.isEmpty()) {
            notFound(channel, getResourceName() + " " + name + " not found.");
            return;
        }

        JsonNode existingResourceAsJsonNode = existingAsObjectNode.get(name);

        JsonNode patchedResourceAsJsonNode;

        try {
            patchedResourceAsJsonNode = applyPatch(jsonPatch, existingResourceAsJsonNode);
        } catch (JsonPatchApplicationException e) {
            log.debug("Error while applying JSON patch", e);
            badRequestResponse(channel, e.getMessage());
            return;
        }
                
        AbstractConfigurationValidator originalValidator = postProcessApplyPatchResult(channel, request, existingResourceAsJsonNode, patchedResourceAsJsonNode, name);

        if(originalValidator != null) {
        	if (!originalValidator.validateSettings()) {
                request.params().clear();
                badRequestResponse(channel, originalValidator);
                return;
            }
        }
        

            AbstractConfigurationValidator validator = getValidator(request, patchedResourceAsJsonNode);

            if (!validator.validateSettings()) {
                request.params().clear();
                badRequestResponse(channel, validator);
                return;
            }

            JsonNode updatedAsJsonNode = existingAsObjectNode.deepCopy().set(name, patchedResourceAsJsonNode);
            
            BytesReference updatedAsBytesReference = new BytesArray(
                    DefaultObjectMapper.objectMapper.writeValueAsString(updatedAsJsonNode).getBytes());

            saveAnUpdateConfigs(client, request, getConfigName(), updatedAsBytesReference, new OnSucessActionListener<IndexResponse>(channel){
                
                @Override
                public void onResponse(IndexResponse response) {
                    successResponse(channel, "'" + name + "' updated.");
                    
                }
            }, existingAsSettings.v1());
    }

    private void handleBulkPatch(RestChannel channel, RestRequest request, Client client,
            Tuple<Long,Settings> existingAsSettings, ObjectNode existingAsObjectNode, JsonNode jsonPatch) throws IOException {

        JsonNode patchedAsJsonNode;

        try {
            patchedAsJsonNode = applyPatch(jsonPatch, existingAsObjectNode);
        } catch (JsonPatchApplicationException e) {
            log.debug("Error while applying JSON patch", e);
            badRequestResponse(channel, e.getMessage());
            return;
        }

        for (String resourceName : existingAsSettings.v2().names()) {
            JsonNode oldResource = existingAsObjectNode.get(resourceName);
            JsonNode patchedResource = patchedAsJsonNode.get(resourceName);

            if (oldResource != null && !oldResource.equals(patchedResource)) {

                if (isReadOnly(existingAsSettings.v2(), resourceName)) {
                    forbidden(channel, "Resource '" + resourceName + "' is read-only.");
                    return;
                }

                if (isHidden(existingAsSettings.v2(), resourceName)) {
                    badRequestResponse(channel, "Resource name '" + resourceName + "' is reserved");
                    return;
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
                        badRequestResponse(channel, originalValidator);
                        return;
                    }
                }

                if (oldResource == null || !oldResource.equals(patchedResource)) {
                    AbstractConfigurationValidator validator = getValidator(request, patchedResource);

                    if (!validator.validateSettings()) {
                        request.params().clear();
                        badRequestResponse(channel, validator);
                        return;
                    }
                }
            }
            
            BytesReference updatedAsBytesReference = new BytesArray(
                    DefaultObjectMapper.objectMapper.writeValueAsString(patchedAsJsonNode).getBytes());

            saveAnUpdateConfigs(client, request, getConfigName(), updatedAsBytesReference, new OnSucessActionListener<IndexResponse>(channel) {

                @Override
                public void onResponse(IndexResponse response) {
                    successResponse(channel, "Resource updated.");
                }
            }, existingAsSettings.v1());

    }

    private JsonNode applyPatch(JsonNode jsonPatch, JsonNode existingResourceAsJsonNode) {
        return JsonPatch.apply(jsonPatch, existingResourceAsJsonNode);
    }

    protected AbstractConfigurationValidator postProcessApplyPatchResult(RestChannel channel, RestRequest request, JsonNode existingResourceAsJsonNode, JsonNode updatedResourceAsJsonNode, String resourceName) {
        // do nothing by default
    	return null;
    }
    
    @Override
    protected void handleApiRequest(RestChannel channel, final RestRequest request, final Client client)
         throws IOException {

        if (request.method() == Method.PATCH) {
            handlePatch(channel, request, client);
        } else {
            super.handleApiRequest(channel, request, client);
        }
    }

    private AbstractConfigurationValidator getValidator(RestRequest request, JsonNode patchedResource)
            throws JsonProcessingException {
        BytesReference patchedResourceAsByteReference = new BytesArray(
                DefaultObjectMapper.objectMapper.writeValueAsString(patchedResource).getBytes());
        return getValidator(request, patchedResourceAsByteReference);
    }
}
