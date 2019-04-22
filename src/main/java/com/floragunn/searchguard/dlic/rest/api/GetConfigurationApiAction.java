/*
 * Copyright 2016-2017 by floragunn GmbH - All rights reserved
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

import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.ConfigurationRepository;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.dlic.rest.validation.NoOpValidator;
import com.floragunn.searchguard.privileges.PrivilegesEvaluator;
import com.floragunn.searchguard.sgconf.impl.CType;
import com.floragunn.searchguard.sgconf.impl.SgDynamicConfiguration;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.google.common.base.Joiner;

/**
 * @deprecated Use GET endpoints without resource ID in resource specific endpoints, e.g. _searchguard/api/roles/
 * Will be removed in SG7.
 */
public class GetConfigurationApiAction extends AbstractApiAction {

	@Inject
	public GetConfigurationApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
			final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
            final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
		controller.registerHandler(Method.GET, "/_searchguard/api/configuration/{configname}", this);
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.CONFIGURATION;
	}

	@Override
	protected void handleGet(RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException{
		
		final String configname = request.param("configname");

		if (configname == null || configname.length() == 0
				|| !CType.lcStringValues().contains(configname)) {
			badRequestResponse(channel, "No configuration name given, must be one of "
					+ Joiner.on(",").join(CType.lcStringValues()));
			return;

		}
		final SgDynamicConfiguration<?> configBuilder = load(CType.fromString(configname), true);
		filter(configBuilder, configname);
		//final Settings config = configBuilder.build();
		
		channel.sendResponse(
				new BytesRestResponse(RestStatus.OK, convertToJson(channel, configBuilder)));
		return;
	}

	protected void filter(SgDynamicConfiguration<?> builder, String resourceName) {
	    // common filtering
	    filter(builder);
	    // filter sensitive resources for internal users
        if (resourceName.equals("internalusers")) {
            filterHashes(builder);
        }	    
	}
        
	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new NoOpValidator(request, ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		// GET is handled by this class directly
		return null;
	}
	
	@Override
    protected CType getConfigName() {
	 // GET is handled by this class directly
	    return null;
    }

	@Override
	protected void consumeParameters(final RestRequest request) {
		request.param("configname");
	}

    private void filterHashes(SgDynamicConfiguration<?> builder) {
        // replace password hashes in addition. We must not remove them from the
        // Builder since this would remove users completely if they
        // do not have any addition properties like roles or attributes
        builder.clearHashes();
    }
}
