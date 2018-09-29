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

import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class ActionGroupsApiTest extends AbstractRestApiUnitTest {

	@Test
	public void testActionGroupsApi() throws Exception {

		setup();

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendHTTPClientCertificate = true;

		// --- GET

		// GET, actiongroup exists
		HttpResponse response = rh.executeGetRequest("/_searchguard/api/actiongroup/CRUD", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();		
		List<String> permissions = settings.getAsList("CRUD.permissions");
		Assert.assertNotNull(permissions);
		Assert.assertEquals(2, permissions.size());
		Assert.assertTrue(permissions.contains("READ"));
		Assert.assertTrue(permissions.contains("WRITE"));

		// GET, actiongroup does not exist
		response = rh.executeGetRequest("/_searchguard/api/actiongroup/nothinghthere", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// GET, old endpoint
		response = rh.executeGetRequest("/_searchguard/api/actiongroup/", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// GET, old endpoint
		response = rh.executeGetRequest("/_searchguard/api/actiongroup", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		
		// GET, new endpoint which replaces configuration endpoint
		response = rh.executeGetRequest("/_searchguard/api/actiongroups/", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// GET, new endpoint which replaces configuration endpoint
		response = rh.executeGetRequest("/_searchguard/api/actiongroups", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
				
		// create index
		setupStarfleetIndex();

		// add user picard, role starfleet, maps to sg_role_starfleet
		addUserWithPassword("picard", "picard", new String[] { "starfleet" }, HttpStatus.SC_CREATED);
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		// checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		// TODO: only one doctype allowed for ES6
		//checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "public", 0);

		// -- DELETE
		// Non-existing role
		rh.sendHTTPClientCertificate = true;

		response = rh.executeDeleteRequest("/_searchguard/api/actiongroup/idonotexist", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// remove action group READ, read access not possible since
		// sg_role_starfleet
		// uses this action group.
		response = rh.executeDeleteRequest("/_searchguard/api/actiongroup/READ", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		rh.sendHTTPClientCertificate = false;
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);

		// put picard in captains role. Role sg_role_captains uses the CRUD
		// action group
		// which uses READ and WRITE action groups. We removed READ, so only
		// WRITE is possible
		addUserWithPassword("picard", "picard", new String[] { "captains" }, HttpStatus.SC_OK);
		checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);

		// now remove also CRUD groups, write also not possible anymore
		rh.sendHTTPClientCertificate = true;
		response = rh.executeDeleteRequest("/_searchguard/api/actiongroup/CRUD", new Header[0]);
		rh.sendHTTPClientCertificate = false;
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);

		// -- PUT

		// put with empty payload, must fail
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_searchguard/api/actiongroup/SOMEGROUP", "", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.PAYLOAD_MANDATORY.getMessage(), settings.get("reason"));

		// put new configuration with invalid payload, must fail
		response = rh.executePutRequest("/_searchguard/api/actiongroup/SOMEGROUP", FileHelper.loadFile("restapi/actiongroup_not_parseable.json"),
				new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.BODY_NOT_PARSEABLE.getMessage(), settings.get("reason"));

		response = rh.executePutRequest("/_searchguard/api/actiongroup/CRUD", FileHelper.loadFile("restapi/actiongroup_crud.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

		rh.sendHTTPClientCertificate = false;

		// write access allowed again, read forbidden, since READ group is still missing
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);

		// restore READ action groups
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_searchguard/api/actiongroup/READ", FileHelper.loadFile("restapi/actiongroup_read.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusCode());

		rh.sendHTTPClientCertificate = false;
		// read/write allowed again
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		checkWriteAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		
		// -- PUT, new JSON format including readonly flag, disallowed in REST API
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_searchguard/api/actiongroup/CRUD", FileHelper.loadFile("restapi/actiongroup_readonly.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

		// -- DELETE read only resource, must be forbidden
		rh.sendHTTPClientCertificate = true;
		response = rh.executeDeleteRequest("/_searchguard/api/actiongroup/GET", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

		// -- PUT read only resource, must be forbidden
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_searchguard/api/actiongroup/GET", FileHelper.loadFile("restapi/actiongroup_read.json"), new Header[0]);
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
		Assert.assertTrue(response.getBody().contains("Resource 'GET' is read-only."));
		
		// -- GET hidden resource, must be 404
        rh.sendHTTPClientCertificate = true;
        response = rh.executeGetRequest("/_searchguard/api/actiongroup/INTERNAL", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());		
		
		// -- DELETE hidden resource, must be 404
        rh.sendHTTPClientCertificate = true;
        response = rh.executeDeleteRequest("/_searchguard/api/actiongroup/INTERNAL", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // -- PUT hidden resource, must be forbidden
        rh.sendHTTPClientCertificate = true;
        response = rh.executePutRequest("/_searchguard/api/actiongroup/INTERNAL", FileHelper.loadFile("restapi/actiongroup_read.json"), new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        
        // -- PATCH
        // PATCH on non-existing resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/actiongroups/imnothere", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/actiongroups/GET", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        
        // PATCH hidden resource, must be not found
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/actiongroups/INTERNAL", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
        
        // PATCH value of hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/actiongroups/CRUD", "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));
        
        // PATCH with relative JSON pointer, must fail
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/actiongroups/CRUD", "[{ \"op\": \"add\", \"path\": \"1/INTERNAL/permissions/-\", \"value\": \"DELETE\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
                
        // PATCH new format
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/actiongroups/CRUD", "[{ \"op\": \"add\", \"path\": \"/permissions/-\", \"value\": \"DELETE\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_searchguard/api/actiongroups/CRUD", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();       
        permissions = settings.getAsList("CRUD.permissions");
        Assert.assertNotNull(permissions);
        Assert.assertEquals(3, permissions.size());
        Assert.assertTrue(permissions.contains("READ"));
        Assert.assertTrue(permissions.contains("WRITE"));        
        Assert.assertTrue(permissions.contains("DELETE"));        

        
	}
}
