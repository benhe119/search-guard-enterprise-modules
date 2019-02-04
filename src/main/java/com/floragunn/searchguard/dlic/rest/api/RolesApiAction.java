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
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.dlic.rest.support.Utils;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.dlic.rest.validation.NoOpValidator;
import com.floragunn.searchguard.dlic.rest.validation.RolesValidator;
import com.floragunn.searchguard.privileges.PrivilegesEvaluator;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.support.ConfigConstants;

public class RolesApiAction extends PatchableResourceApiAction {

	protected final Logger log = LogManager.getLogger(this.getClass());

	@Inject
	public RolesApiAction(Settings settings, final Path configPath, RestController controller, Client client,
			AdminDNs adminDNs, IndexBaseConfigurationRepository cl, ClusterService cs,
			final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool,
			AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
				auditLog);
		controller.registerHandler(Method.GET, "/_searchguard/api/roles/", this);
		controller.registerHandler(Method.GET, "/_searchguard/api/roles/{name}", this);
		controller.registerHandler(Method.DELETE, "/_searchguard/api/roles/{name}", this);
		controller.registerHandler(Method.PUT, "/_searchguard/api/roles/{name}", this);
		controller.registerHandler(Method.PATCH, "/_searchguard/api/roles/", this);
		controller.registerHandler(Method.POST, "/_searchguard/api/roles/", this);
		controller.registerHandler(Method.PATCH, "/_searchguard/api/roles/{name}", this);

	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ROLES;
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new RolesValidator(request, ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		return "role";
	}

	@Override
	protected String getConfigName() {
		return ConfigConstants.CONFIGNAME_ROLES;
	}

	@Override
	protected void handlePost(final RestChannel channel, final RestRequest request, final Client client,
			final Settings.Builder additionalSettings) throws IOException {

		XContentParser contentParser = request.contentParser();

		Map<String, Object> structuredMap = contentParser.map();

		if ("formatUpgrade".equalsIgnoreCase(String.valueOf(structuredMap.get("action")))) {
			handleUpgrade(channel, request, client, additionalSettings);
		} else {
			badRequestResponse(channel, "Invalid action parameter: " + request.param("action"));
		}
	}

	private void handleUpgrade(final RestChannel channel, final RestRequest request, final Client client,
			final Settings.Builder additionalSettings) {
		Tuple<Long, Settings> existingAsSettings = loadAsSettings(ConfigConstants.CONFIGNAME_ROLES, false);

		Set<String> sgRoles = existingAsSettings.v2().names();
		Settings.Builder updatedSettingsBuilder = Settings.builder();
		updatedSettingsBuilder.put(existingAsSettings.v2());

		log.info("Upgrading roles config:\n" + existingAsSettings);

		int updateCount = 0;

		for (String sgRole : sgRoles) {

			Settings tenants = existingAsSettings.v2().getByPrefix(sgRole + ".tenants.");

			if (tenants == null) {
				continue;
			}

			for (String tenant : tenants.names()) {

				Settings tenantSettings = tenants.getAsSettings(tenant);

				if (!tenantSettings.isEmpty()) {
					// New style config
					continue;
				} else {
					// Legacy config

					updatedSettingsBuilder.remove(sgRole + ".tenants." + tenant);

					// TODO check if used permissions are right

					String legacyTenantConfig = tenants.get(tenant, "RO");

					if ("RW".equalsIgnoreCase(legacyTenantConfig)) {
						updatedSettingsBuilder.putList(sgRole + ".tenants." + tenant + ".applications",
								Collections.singletonList("kibana:saved_objects/*/*"));
					} else {
						updatedSettingsBuilder.putList(sgRole + ".tenants." + tenant + ".applications",
								Collections.singletonList("kibana:saved_objects/*/read"));
					}

					updateCount++;
				}
			}
		}

		log.info("Upgraded roles config. " + updateCount + " changes.");

		if (updateCount != 0) {

			// XXX is there an easier way to convert to BytesReference?
			BytesReference updatedConfig = Utils
					.convertStructuredMapToBytes(Utils.convertJsonToxToStructuredMap(updatedSettingsBuilder.build()));

			saveAnUpdateConfigs(client, request, getConfigName(), updatedConfig,
					new OnSucessActionListener<IndexResponse>(channel) {

						@Override
						public void onResponse(IndexResponse response) {
							successResponse(channel, updatedConfig.utf8ToString());
						}
					}, existingAsSettings.v1());
		} else {
			successResponse(channel, existingAsSettings.v2().toString());
		}
	}
}
