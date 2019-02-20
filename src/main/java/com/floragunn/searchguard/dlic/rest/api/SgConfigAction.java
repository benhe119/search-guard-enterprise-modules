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

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.CType;
import com.floragunn.searchguard.configuration.ConfigurationRepository;
import com.floragunn.searchguard.configuration.SgDynamicConfiguration;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.dlic.rest.validation.NoOpValidator;
import com.floragunn.searchguard.privileges.PrivilegesEvaluator;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;

public class SgConfigAction extends AbstractApiAction {

	@Inject
	public SgConfigAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
			final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
			final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
		controller.registerHandler(Method.GET, "/_searchguard/api/sgconfig/", this);
	}



	@Override
	protected void handleGet(RestChannel channel, RestRequest request, Client client,
			final Settings.Builder additionalSettingsBuilder) {

		final SgDynamicConfiguration<?> configurationSettings = load(getConfigName(), true);

		channel.sendResponse(
				new BytesRestResponse(RestStatus.OK, convertToJson(channel, configurationSettings)));
	}
	
	@Override
	protected void handlePut(RestChannel channel, final RestRequest request, final Client client,
			final Settings.Builder additionalSettings) {
		notImplemented(channel, Method.PUT);
	}

	@Override
	protected void handleDelete(RestChannel channel, final RestRequest request, final Client client,
			final Settings.Builder additionalSettings) {
		notImplemented(channel, Method.DELETE);
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new NoOpValidator(request, ref, this.settings, param);
	}

    @Override
    protected CType getConfigName() {
        return CType.CONFIG;
    }

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.SGCONFIG;
	}

	@Override
	protected String getResourceName() {
		// not needed, no single resource
		return null;
	}

}
