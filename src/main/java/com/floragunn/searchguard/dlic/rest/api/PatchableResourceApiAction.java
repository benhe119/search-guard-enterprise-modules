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

import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
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

        if (name == null || name.length() == 0) {
            return badRequestResponse("No " + getResourceName() + " specified");
        }

        Settings existingAsSettings = loadAsSettings(getConfigName(), false);

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

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonPatch = objectMapper.readTree(request.content().utf8ToString());
        JsonNode existingAsJsonNode = Utils.convertJsonToJackson(existingAsSettings);

        if (!(existingAsJsonNode instanceof ObjectNode)) {
            return internalErrorResponse("Config " + getConfigName() + " is malformed");
        }

        ObjectNode existingAsObjectNode = (ObjectNode) existingAsJsonNode;

        JsonNode existingResourceAsJsonNode = existingAsJsonNode.get(name);

        JsonNode patchedResourceAsJsonNode;

        try {
            patchedResourceAsJsonNode = applyPatch(jsonPatch, existingResourceAsJsonNode);
        } catch (JsonPatchApplicationException e) {
            return badRequestResponse(e.getMessage());
        }
        
        BytesReference patchedResourceAsByteReference = new BytesArray(
                objectMapper.writeValueAsString(patchedResourceAsJsonNode).getBytes());
        
        AbstractConfigurationValidator validator = getValidator(request.method(), patchedResourceAsByteReference);

        if (!validator.validateSettings()) {
            request.params().clear();
            return new Tuple<String[], RestResponse>(new String[0],
                    new BytesRestResponse(RestStatus.BAD_REQUEST, validator.errorsAsXContent()));
        }        
        
        JsonNode updatedAsJsonNode = existingAsObjectNode.deepCopy().set(name, patchedResourceAsJsonNode);

        BytesReference updatedAsBytesReference = new BytesArray(
                objectMapper.writeValueAsString(updatedAsJsonNode).getBytes());

        save(client, request, getConfigName(), updatedAsBytesReference);

        return successResponse("'" + name + "' updated.", getConfigName());

    }

    protected JsonNode applyPatch(JsonNode jsonPatch, JsonNode existingResourceAsJsonNode) {
        return JsonPatch.apply(jsonPatch, existingResourceAsJsonNode);
    }

    protected Tuple<String[], RestResponse> handleApiRequest(final RestRequest request, final Client client)
            throws Throwable {

        if (request.method() == Method.PATCH) {
            return handlePatch(request, client);
        } else {
            return super.handleApiRequest(request, client);
        }
    }

}
