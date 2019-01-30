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
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.dlic.rest.validation.NoOpValidator;
import com.floragunn.searchguard.privileges.PrivilegesEvaluator;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;

public class AuthTokenProcessorAction extends AbstractApiAction {
	@Inject
	public AuthTokenProcessorAction(final Settings settings, final Path configPath, final RestController controller,
			final Client client, final AdminDNs adminDNs, final IndexBaseConfigurationRepository cl,
			final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
			ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
				auditLog);

		controller.registerHandler(Method.POST, "/_searchguard/api/authtoken", this);
	}

	@Override
	protected void handlePost(RestChannel channel, final RestRequest request, final Client client,
			final Settings.Builder additionalSettings) {

		// Just do nothing here. Eligible authenticators will intercept calls and
		// provide own responses.

		channel.sendResponse(new BytesRestResponse(RestStatus.OK, ""));
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new NoOpValidator(request, ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		return "authtoken";
	}

	@Override
	protected String getConfigName() {
		return null;
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.AUTHTOKEN;
	}
	

	public static class Response {
		private String authorization;

		public String getAuthorization() {
			return authorization;
		}

		public void setAuthorization(String authorization) {
			this.authorization = authorization;
		}
	}
}
