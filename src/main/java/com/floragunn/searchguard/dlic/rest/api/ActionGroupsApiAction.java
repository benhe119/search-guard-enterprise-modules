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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
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
import com.floragunn.searchguard.dlic.rest.validation.ActionGroupValidator;
import com.floragunn.searchguard.privileges.PrivilegesEvaluator;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.support.ConfigConstants;
import com.google.common.base.Strings;

public class ActionGroupsApiAction extends PatchableResourceApiAction {

	protected final Logger log = LogManager.getLogger(this.getClass());

	@Inject
	public ActionGroupsApiAction(final Settings settings, final Path configPath, final RestController controller,
			final Client client, final AdminDNs adminDNs, final IndexBaseConfigurationRepository cl,
			final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
			ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
				auditLog);

		// legacy mapping for backwards compatibility
		// TODO: remove in SG7
		controller.registerHandler(Method.GET, "/_searchguard/api/actiongroup/{name}", this);
		controller.registerHandler(Method.GET, "/_searchguard/api/actiongroup/", this);
		controller.registerHandler(Method.DELETE, "/_searchguard/api/actiongroup/{name}", this);
		controller.registerHandler(Method.PUT, "/_searchguard/api/actiongroup/{name}", this);

		// corrected mapping, introduced in SG6
		controller.registerHandler(Method.GET, "/_searchguard/api/actiongroups/{name}", this);
		controller.registerHandler(Method.GET, "/_searchguard/api/actiongroups/", this);
		controller.registerHandler(Method.DELETE, "/_searchguard/api/actiongroups/{name}", this);
		controller.registerHandler(Method.PUT, "/_searchguard/api/actiongroups/{name}", this);
		controller.registerHandler(Method.PATCH, "/_searchguard/api/actiongroups/", this);
		controller.registerHandler(Method.PATCH, "/_searchguard/api/actiongroups/{name}", this);

	}

	@Override
	protected AbstractConfigurationValidator getValidator(final RestRequest request, BytesReference ref,
			Object... param) {
		return new ActionGroupValidator(request, ref, this.settings, param);
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.ACTIONGROUPS;
	}

	@Override
	protected String getResourceName() {
		return "actiongroup";
	}

	@Override
	protected String getConfigName() {
		return ConfigConstants.CONFIGNAME_ACTION_GROUPS;
	}

	@Override
	protected void consumeParameters(final RestRequest request) {
		request.param("application");
		request.param("name");
	}

	@Override
	protected void handleGet(final RestChannel channel, RestRequest request, Client client, Builder additionalSettings)
			throws IOException {

		String application = request.param("application");
		String resourcename = request.param("name");

		if (Strings.isNullOrEmpty(application) || !Strings.isNullOrEmpty(resourcename)) {
			super.handleGet(channel, request, client, additionalSettings);
		}

		boolean negate = false;

		if (application.startsWith("-")) {
			application = application.substring(1);
			negate = true;
		}

		final Settings configurationSettings = filterActionGroupsByApplication(
				loadAsSettings(getConfigName(), true).v2(), application, negate);

		channel.sendResponse(new BytesRestResponse(RestStatus.OK, convertToJson(channel, configurationSettings)));
	}

	private Settings filterActionGroupsByApplication(Settings settings, String application, boolean negate) {
		Settings.Builder resultBuilder = Settings.builder();

		for (Map.Entry<String, Settings> entry : settings.getAsGroups(true).entrySet()) {
			List<String> matchingPermissions = getMatchingPermissions(settings, entry.getKey(), application,
					entry.getValue(), negate);

			if (matchingPermissions != null) {
				resultBuilder.putList(entry.getKey() + ".permissions", matchingPermissions);

				if (entry.getValue().hasValue("readonly")) {
					resultBuilder.put(entry.getKey() + ".readonly", entry.getValue().getAsBoolean("readonly", false));
				}
			}

		}

		return resultBuilder.build();
	}

	private List<String> getMatchingPermissions(Settings settings, String key, String application, Settings subSettings,
			boolean negate) {
		List<String> result = new ArrayList<>(subSettings.size());

		if (subSettings.size() == 0) {
			return result;
		}

		for (String permission : subSettings.getAsList("permissions")) {
			if (matchPermission(settings, key, permission, application, negate, 10)) {
				result.add(permission);
			}
		}

		if (result.size() > 0) {
			return result;
		} else {
			return null;
		}

	}

	private boolean containsActionByApplication(Settings settings, String key, String application, boolean negate,
			int maxRecursionDepth) {
		if (maxRecursionDepth <= 0) {
			log.warn("Max recursion depth exceeded for action group " + key);
			return false;
		}

		List<String> permissions = settings.getAsList(key + ".permissions");

		if (permissions == null) {
			return false;
		}

		for (String permission : permissions) {
			if (matchPermission(settings, key, permission, application, negate, maxRecursionDepth)) {
				return true;
			}
		}

		return false;
	}

	private boolean matchPermission(Settings settings, String key, String permission, String application,
			boolean negate, int maxRecursionDepth) {
		if (permission == null) {
			return false;
		}

		if (permission.startsWith(application + ":")) {
			return true ^ negate;
		}

		if (!key.equals(permission)
				&& (settings.hasValue(permission) || settings.hasValue(permission + ".permissions"))) {
			if (containsActionByApplication(settings, permission, application, negate, maxRecursionDepth - 1)) {
				return true;
			}
		}

		return false ^ negate;
	}
}
