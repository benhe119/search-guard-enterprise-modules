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


import java.nio.file.Path;
import java.util.Set;

import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.dlic.rest.validation.NoOpValidator;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.support.ConfigConstants;
import com.google.common.base.Joiner;

/**
 * @deprecated Use GET endpoints without resource ID in resource specific endpoints, e.g. _searchguard/api/roles/
 * Will be removed in SG7.
 */
public class GetConfigurationApiAction extends AbstractApiAction {

	@Inject
	public GetConfigurationApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
			final AdminDNs adminDNs, final IndexBaseConfigurationRepository cl, final ClusterService cs,
            final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
		controller.registerHandler(Method.GET, "/_searchguard/api/configuration/{configname}", this);
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.CONFIGURATION;
	}

	@Override
	protected Tuple<String[], RestResponse> handleGet(RestRequest request, Client client,
			final Settings.Builder additionalSettingsBuilder) throws Throwable {
		
		final String configname = request.param("configname");

		if (configname == null || configname.length() == 0
				|| !ConfigConstants.CONFIG_NAMES.contains(configname)) {
			return badRequestResponse("No configuration name given, must be one of "
					+ Joiner.on(",").join(ConfigConstants.CONFIG_NAMES));

		}

		final Settings.Builder configBuilder = load(configname);
		filter(configBuilder, configname);
		final Settings config = configBuilder.build();
		
		return new Tuple<String[], RestResponse>(new String[0],
				new BytesRestResponse(RestStatus.OK, convertToJson(config)));
	}

	protected void filter(Settings.Builder builder, String resourceName) {
	    // common filtering
	    filter(builder);
	    // filter sensitive resources for internal users
        if (resourceName.equals("internalusers")) {
            filterHashes(builder);
        }	    
	}
        
	@Override
	protected AbstractConfigurationValidator getValidator(Method method, BytesReference ref) {
		return new NoOpValidator(method, ref);
	}

	@Override
	protected String getResourceName() {
		// GET is handled by this class directly
		return null;
	}

	@Override
	protected String getConfigName() {
		// GET is handled by this class directly
		return null;
	}

	@Override
	protected void consumeParameters(final RestRequest request) {
		request.param("configname");
	}

    private void filterHashes(Settings.Builder builder) {
        // replace password hashes in addition. We must not remove them from the
        // Builder since this would remove users completely if they
        // do not have any addition properties like roles or attributes
        Set<String> entries = builder.build().getAsGroups().keySet();
        for (String key : entries) {
            builder.put(key + ".hash", "");
        }
    }
}
