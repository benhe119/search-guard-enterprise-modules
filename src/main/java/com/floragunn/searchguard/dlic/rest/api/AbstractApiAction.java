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
import java.util.Arrays;
import java.util.Collections;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import com.floragunn.searchguard.DefaultObjectMapper;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateAction;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateNodeResponse;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateRequest;
import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse;
import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.configuration.AdminDNs;
import com.floragunn.searchguard.configuration.ConfigurationRepository;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator.ErrorType;
import com.floragunn.searchguard.privileges.PrivilegesEvaluator;
import com.floragunn.searchguard.sgconf.DynamicConfigFactory;
import com.floragunn.searchguard.sgconf.Hideable;
import com.floragunn.searchguard.sgconf.StaticDefinable;
import com.floragunn.searchguard.sgconf.impl.CType;
import com.floragunn.searchguard.sgconf.impl.SgDynamicConfiguration;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.User;

public abstract class AbstractApiAction extends BaseRestHandler {

	protected final Logger log = LogManager.getLogger(this.getClass());

	protected final ConfigurationRepository cl;
	protected final ClusterService cs;
	final ThreadPool threadPool;
	private String searchguardIndex;
	private final RestApiPrivilegesEvaluator restApiPrivilegesEvaluator;
	protected final Boolean acceptInvalidLicense;
	protected final AuditLog auditLog;
	protected final Settings settings;

	protected AbstractApiAction(final Settings settings, final Path configPath, final RestController controller,
			final Client client, final AdminDNs adminDNs, final ConfigurationRepository cl,
			final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
			ThreadPool threadPool, AuditLog auditLog) {
		super(settings);
		this.settings = settings;
		this.searchguardIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME,
				ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
		this.acceptInvalidLicense = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_UNSUPPORTED_RESTAPI_ACCEPT_INVALID_LICENSE, Boolean.FALSE);

		this.cl = cl;
		this.cs = cs;
		this.threadPool = threadPool;
		this.restApiPrivilegesEvaluator = new RestApiPrivilegesEvaluator(settings, adminDNs, evaluator,
				principalExtractor, configPath, threadPool);
		this.auditLog = auditLog;
	}

	protected abstract AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params);

	protected abstract String getResourceName();

	protected abstract CType getConfigName();

	protected void handleApiRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {

		// validate additional settings, if any
		AbstractConfigurationValidator validator = getValidator(request, request.content());
		if (!validator.validateSettings()) {
			request.params().clear();
			channel.sendResponse(new BytesRestResponse(RestStatus.BAD_REQUEST, validator.errorsAsXContent(channel)));
			return;
		}
		switch (request.method()) {
		case DELETE:
			handleDelete(channel,request, client, validator.getContentAsNode()); break;
		case POST:
			handlePost(channel,request, client, validator.getContentAsNode());break;
		case PUT:
			handlePut(channel,request, client, validator.getContentAsNode());break;
		case GET:
             handleGet(channel,request, client, validator.getContentAsNode());break;
		default:
			throw new IllegalArgumentException(request.method() + " not supported");
		}
	}

	protected void handleDelete(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			badRequestResponse(channel, "No " + getResourceName() + " specified.");
			return;
		}

		final SgDynamicConfiguration<?> existingAsSettings = load(getConfigName(), false);
		
		if (isHidden(existingAsSettings, name)) {
            notFound(channel, getResourceName() + " " + name + " not found.");
            return;
		}
		
		if (isReserved(existingAsSettings, name)) {
			forbidden(channel, "Resource '"+ name +"' is read-only.");
			return;
		}
		
        boolean existed = existingAsSettings.exists(name);
        existingAsSettings.remove(name);
		
		if (existed) {
			saveAnUpdateConfigs(client, request, getConfigName(), existingAsSettings, new OnSucessActionListener<IndexResponse>(channel) {
                
                @Override
                public void onResponse(IndexResponse response) {
                    successResponse(channel, "'" + name + "' deleted.");
                }
            });
			
		} else {
			notFound(channel, getResourceName() + " " + name + " not found.");
		}
	}

	protected void handlePut(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
		
		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			badRequestResponse(channel, "No " + getResourceName() + " specified.");
			return;
		}

		final SgDynamicConfiguration<?> existingAsSettings = load(getConfigName(), false);

		if (isHidden(existingAsSettings, name)) {
            forbidden(channel, "Resource '"+ name +"' is not available.");
            return;
		}
		
		if (isReserved(existingAsSettings, name)) {
			forbidden(channel, "Resource '"+ name +"' is read-only.");
			return;
		}
		
		if (log.isTraceEnabled() && content != null) {
			log.trace(content.toString());
		}
		
		boolean existed = existingAsSettings.exists(name);
		existingAsSettings.putCObject(name, DefaultObjectMapper.readTree(content, existingAsSettings.getImplementingClass()));
		
		saveAnUpdateConfigs(client, request, getConfigName(), existingAsSettings, new OnSucessActionListener<IndexResponse>(channel) {

            @Override
            public void onResponse(IndexResponse response) {
                if (existed) {
                    successResponse(channel, "'" + name + "' updated.");
                } else {
                    createdResponse(channel, "'" + name + "' created.");
                }
                
            }
        });
		
	}

	protected void handlePost(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException {
		notImplemented(channel, Method.POST);
	}

	protected void handleGet(final RestChannel channel, RestRequest request, Client client, final JsonNode content)
	        throws IOException{
	    
		final String resourcename = request.param("name");

		final SgDynamicConfiguration<?> settingsBuilder = load(getConfigName(), true);
		filter(settingsBuilder);
		

		// no specific resource requested, return complete config
		if (resourcename == null || resourcename.length() == 0) {
		     
			channel.sendResponse(
					new BytesRestResponse(RestStatus.OK, convertToJson(channel, settingsBuilder)));
			return;
		}

		if (!settingsBuilder.exists(resourcename)) {
			notFound(channel, "Resource '" + resourcename + "' not found.");
			return;
		}	

		settingsBuilder.removeOthers(resourcename);
		channel.sendResponse(
            		new BytesRestResponse(RestStatus.OK, convertToJson(channel, settingsBuilder)));

		return;
	}

	protected final SgDynamicConfiguration<?> load(final CType config, boolean logComplianceEvent) {
	    SgDynamicConfiguration<?> loaded = cl.getConfigurationsFromIndex(Collections.singleton(config), logComplianceEvent).get(config).deepClone();
	    return DynamicConfigFactory.addStatics(loaded);
	}

	protected boolean ensureIndexExists() {
		if (!cs.state().metaData().hasConcreteIndex(this.searchguardIndex)) {
			return false;
		}
		return true;
	}

	protected void filter(SgDynamicConfiguration<?> builder) {
        builder.removeHidden();
        builder.set_sg_meta(null);
	}
	
	abstract class OnSucessActionListener<Response> implements ActionListener<Response> {

	    private final RestChannel channel;

        public OnSucessActionListener(RestChannel channel) {
            super();
            this.channel = channel;
        }

        @Override
        public final void onFailure(Exception e) {
            internalErrorResponse(channel, "Error "+e.getMessage());
        }
	    
	}

	protected void saveAnUpdateConfigs(final Client client, final RestRequest request, final CType cType,
	        final SgDynamicConfiguration<?> settings, OnSucessActionListener<IndexResponse> actionListener) {
		final IndexRequest ir = new IndexRequest(this.searchguardIndex);

		final String type = "_doc";
		final String id = cType.toLCString();

		settings.removeStatic();
		
		try {
            client.index(ir.type(type).id(id)
                    .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                    .setIfSeqNo(settings.getSeqNo())
                    .setIfPrimaryTerm(settings.getPrimaryTerm())
                    .source(id, XContentHelper.toXContent(settings, XContentType.JSON, false)),
                    new ConfigUpdatingActionListener<IndexResponse>(client, actionListener));
        } catch (IOException e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
	}
	
	private static class ConfigUpdatingActionListener<Response> implements ActionListener<Response>{

	    private final Client client;
	    private final ActionListener<Response> delegate;

        public ConfigUpdatingActionListener(Client client, ActionListener<Response> delegate) {
            super();
            this.client = client;
            this.delegate = delegate;
        }

        @Override
        public void onResponse(Response response) {
            
            final ConfigUpdateRequest cur = new ConfigUpdateRequest(new String[] { "config", "roles", "rolesmapping", "internalusers", "actiongroups" });
            
            client.execute(ConfigUpdateAction.INSTANCE, cur, new ActionListener<ConfigUpdateResponse>() {
                @Override
                public void onResponse(final ConfigUpdateResponse ur) {
                    if(ur.hasFailures()) {
                        delegate.onFailure(ur.failures().get(0));
                        return;
                    }
                    delegate.onResponse(response);
                }
                
                @Override
                public void onFailure(final Exception e) {
                    delegate.onFailure(e);
                }
            });
            
        }

        @Override
        public void onFailure(Exception e) {
            delegate.onFailure(e);
        }
	    
	}

    @Override
    protected final RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        // consume all parameters first so we can return a correct HTTP status,
        // not 400
        consumeParameters(request);

        // check if SG index has been initialized
        if (!ensureIndexExists()) {
            return channel -> channel.sendResponse(
                    new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, ErrorType.SG_NOT_INITIALIZED.getMessage())); // TODO
                                                                                                                         // return
                                                                                                                         // json
        }

        // check if request is authorized
        String authError = restApiPrivilegesEvaluator.checkAccessPermissions(request, getEndpoint());

        if (authError != null) {
            logger.error("No permission to access REST API: " + authError);
            final User user = (User) threadPool.getThreadContext().getTransient(ConfigConstants.SG_USER);
            auditLog.logMissingPrivileges(authError, user == null ? null : user.getName(), request);
            // for rest request
            request.params().clear();
            return channel -> forbidden(channel, "No permission to access REST API: " + authError);
        }

        final Object originalUser = threadPool.getThreadContext().getTransient(ConfigConstants.SG_USER);
        final Object originalRemoteAddress = threadPool.getThreadContext()
                .getTransient(ConfigConstants.SG_REMOTE_ADDRESS);
        final Object originalOrigin = threadPool.getThreadContext().getTransient(ConfigConstants.SG_ORIGIN);

        return channel -> {
            
            try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {

                threadPool.getThreadContext().putHeader(ConfigConstants.SG_CONF_REQUEST_HEADER, "true");
                threadPool.getThreadContext().putTransient(ConfigConstants.SG_USER, originalUser);
                threadPool.getThreadContext().putTransient(ConfigConstants.SG_REMOTE_ADDRESS, originalRemoteAddress);
                threadPool.getThreadContext().putTransient(ConfigConstants.SG_ORIGIN, originalOrigin);

                handleApiRequest(channel, request, client);
            }
        };
    }

	protected boolean checkConfigUpdateResponse(final ConfigUpdateResponse response) {

		final int nodeCount = cs.state().getNodes().getNodes().size();
		final int expectedConfigCount = 1;

		boolean success = response.getNodes().size() == nodeCount;
		if (!success) {
			logger.error(
					"Expected " + nodeCount + " nodes to return response, but got only " + response.getNodes().size());
		}

		for (final String nodeId : response.getNodesMap().keySet()) {
			final ConfigUpdateNodeResponse node = response.getNodesMap().get(nodeId);
			final boolean successNode = node.getUpdatedConfigTypes() != null
					&& node.getUpdatedConfigTypes().length == expectedConfigCount;

			if (!successNode) {
				logger.error("Expected " + expectedConfigCount + " config types for node " + nodeId + " but got only "
						+ Arrays.toString(node.getUpdatedConfigTypes()));
			}

			success = success && successNode;
		}

		return success;
	}

	protected static XContentBuilder convertToJson(RestChannel channel, ToXContent settings) {
		try {
            XContentBuilder builder = channel.newBuilder();
            settings.toXContent(builder, ToXContent.EMPTY_PARAMS);
            return builder;
        } catch (IOException e) {
            throw ExceptionsHelper.convertToElastic(e);
        }
	}

	protected void response(RestChannel channel, RestStatus status, String statusString, String message) {

		try {
			final XContentBuilder builder = channel.newBuilder();
			builder.startObject();
			builder.field("status", statusString);
			builder.field("message", message);
			builder.endObject();
			channel.sendResponse(new BytesRestResponse(status, builder));
		} catch (IOException e) {
		    throw ExceptionsHelper.convertToElastic(e);
		}
	}

	protected void successResponse(RestChannel channel, String message) {
		response(channel, RestStatus.OK, RestStatus.OK.name(), message);
	}

	protected void createdResponse(RestChannel channel, String message) {
		response(channel, RestStatus.CREATED, RestStatus.CREATED.name(), message);
	}

	protected void badRequestResponse(RestChannel channel, String message) {
		response(channel, RestStatus.BAD_REQUEST, RestStatus.BAD_REQUEST.name(), message);
	}

	protected void notFound(RestChannel channel, String message) {
		response(channel, RestStatus.NOT_FOUND, RestStatus.NOT_FOUND.name(), message);
	}

	protected void forbidden(RestChannel channel, String message) {
		response(channel, RestStatus.FORBIDDEN, RestStatus.FORBIDDEN.name(), message);
	}

	protected void internalErrorResponse(RestChannel channel, String message) {
		response(channel, RestStatus.INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.name(), message);
	}

	protected void unprocessable(RestChannel channel, String message) {
		response(channel, RestStatus.UNPROCESSABLE_ENTITY, RestStatus.UNPROCESSABLE_ENTITY.name(), message);
	}

	protected void notImplemented(RestChannel channel, Method method) {
		response(channel, RestStatus.NOT_IMPLEMENTED, RestStatus.NOT_IMPLEMENTED.name(),
				"Method " + method.name() + " not supported for this action.");
	}
	
	protected final boolean isReserved(SgDynamicConfiguration<?> settings, String resourceName) {
	    if(isStatic(settings, resourceName)) { //static is also always reserved
	        return true;
	    }
	    
	    final Object o = settings.getCEntry(resourceName);
	    return o != null && o instanceof Hideable && ((Hideable) o).isReserved();
	}

    protected final boolean isHidden(SgDynamicConfiguration<?> settings, String resourceName) {
        final Object o = settings.getCEntry(resourceName);
        return o != null && o instanceof Hideable && ((Hideable) o).isHidden();
    }
    
    protected final boolean isStatic(SgDynamicConfiguration<?> settings, String resourceName) {
        final Object o = settings.getCEntry(resourceName);
        return o != null && o instanceof StaticDefinable && ((StaticDefinable) o).isStatic();
    }
	
	/**
	 * Consume all defined parameters for the request. Before we handle the
	 * request in subclasses where we actually need the parameter, some global
	 * checks are performed, e.g. check whether the SG index exists. Thus, the
	 * parameter(s) have not been consumed, and ES will always return a 400 with
	 * an internal error message.
	 * 
	 * @param request
	 */
	protected void consumeParameters(final RestRequest request) {
		request.param("name");
	}

	@Override
	public String getName() {
		return getClass().getSimpleName();
	}

	protected abstract Endpoint getEndpoint();

}
