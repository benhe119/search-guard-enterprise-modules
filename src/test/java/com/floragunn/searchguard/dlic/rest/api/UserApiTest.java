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

import java.net.URLEncoder;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.dlic.rest.validation.AbstractConfigurationValidator;
import com.floragunn.searchguard.sgconf.impl.CType;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class UserApiTest extends AbstractRestApiUnitTest {

	@Test
	public void testUserApi() throws Exception {

		setup();

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendHTTPClientCertificate = true;

		// initial configuration, 5 users
		HttpResponse response = rh
				.executeGetRequest("_searchguard/api/configuration/" + CType.INTERNALUSERS.toLCString());
		Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(20, settings.size());
		// --- GET

		// GET, user admin, exists
		response = rh.executeGetRequest("/_searchguard/api/user/admin", new Header[0]);
		Assert.assertEquals(response.getBody(), HttpStatus.SC_OK, response.getStatusCode());
		System.out.println(response.getBody());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(4, settings.size());
		// hash must be filtered
		Assert.assertEquals("", settings.get("admin.hash"));

		// GET, user does not exist
		response = rh.executeGetRequest("/_searchguard/api/user/nothinghthere", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// GET, new URL endpoint in SG6
		response = rh.executeGetRequest("/_searchguard/api/user/", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// GET, new URL endpoint in SG6
		response = rh.executeGetRequest("/_searchguard/api/user", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());

		// -- PUT

		// no username given
		response = rh.executePutRequest("/_searchguard/api/user/", "{\"hash\": \"123\"}", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

		// Faulty JSON payload
		response = rh.executePutRequest("/_searchguard/api/user/nagilum", "{some: \"thing\" asd  other: \"thing\"}",
				new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.get("reason"), AbstractConfigurationValidator.ErrorType.BODY_NOT_PARSEABLE.getMessage());

		// Missing quotes in JSON - parseable in 6.x, but wrong config keys
		response = rh.executePutRequest("/_searchguard/api/user/nagilum", "{some: \"thing\", other: \"thing\"}",
				new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		//JK: this should be "Could not parse content of request." because JSON is truly invalid
		//Assert.assertEquals(settings.get("reason"), AbstractConfigurationValidator.ErrorType.INVALID_CONFIGURATION.getMessage());
		//Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("some"));
		//Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("other"));

		// Wrong config keys
		response = rh.executePutRequest("/_searchguard/api/user/nagilum", "{\"some\": \"thing\", \"other\": \"thing\"}",
				new Header[0]);
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(settings.get("reason"), AbstractConfigurationValidator.ErrorType.INVALID_CONFIGURATION.getMessage());
		Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("some"));
		Assert.assertTrue(settings.get(AbstractConfigurationValidator.INVALID_KEYS_KEY + ".keys").contains("other"));
		
        // -- PATCH
        // PATCH on non-existing resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers/imnothere", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers/sarek", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        
        // PATCH hidden resource, must be not found
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers/q", "[{ \"op\": \"add\", \"path\": \"/a/b/c\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
        
        // PATCH value of hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers/test", "[{ \"op\": \"add\", \"path\": \"/hidden\", \"value\": true }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody(), response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));
        		
        // PATCH password
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers/test", "[{ \"op\": \"add\", \"path\": \"/password\", \"value\": \"neu\" }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_searchguard/api/internalusers/test", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();       
        Assert.assertFalse(settings.hasValue("test.password"));
        Assert.assertTrue(settings.hasValue("test.hash"));
        
        // -- PATCH on whole config resource
        // PATCH on non-existing resource
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/imnothere/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // PATCH read only resource, must be forbidden
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/sarek/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        
        // PATCH hidden resource, must be bad request
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/q/a\", \"value\": [ \"foo\", \"bar\" ] }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        
        // PATCH value of hidden flag, must fail with validation error
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/test/hidden\", \"value\": true }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().matches(".*\"invalid_keys\"\\s*:\\s*\\{\\s*\"keys\"\\s*:\\s*\"hidden\"\\s*\\}.*"));
 
        // PATCH
        rh.sendHTTPClientCertificate = true;
        response = rh.executePatchRequest("/_searchguard/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/bulknew1\", \"value\": {\"password\": \"bla\", \"roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        response = rh.executeGetRequest("/_searchguard/api/internalusers/bulknew1", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();       
        Assert.assertFalse(settings.hasValue("bulknew1.password"));
        Assert.assertTrue(settings.hasValue("bulknew1.hash"));        
        List<String> roles = settings.getAsList("bulknew1.roles");
        Assert.assertEquals(1, roles.size());
        Assert.assertTrue(roles.contains("vulcan"));
        
		// add user with correct setting. User is in role "sg_all_access"

		// check access not allowed
		checkGeneralAccess(HttpStatus.SC_UNAUTHORIZED, "nagilum", "nagilum");

		// add/update user, user is read only, forbidden
		rh.sendHTTPClientCertificate = true;
		addUserWithHash("sarek", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
				HttpStatus.SC_FORBIDDEN);

        // add/update user, user is hidden, forbidden
        rh.sendHTTPClientCertificate = true;
        addUserWithHash("q", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_FORBIDDEN);

		// add users
		rh.sendHTTPClientCertificate = true;
		addUserWithHash("nagilum", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
				HttpStatus.SC_CREATED);

		// access must be allowed now
		checkGeneralAccess(HttpStatus.SC_OK, "nagilum", "nagilum");

		// try remove user, no username
		rh.sendHTTPClientCertificate = true;
		response = rh.executeDeleteRequest("/_searchguard/api/user", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

		// try remove user, nonexisting user
		response = rh.executeDeleteRequest("/_searchguard/api/user/picard", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());

		// try remove readonly user
		response = rh.executeDeleteRequest("/_searchguard/api/user/sarek", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());

        // try remove hidden user
        response = rh.executeDeleteRequest("/_searchguard/api/user/q", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());		
		
		// now really remove user
		deleteUser("nagilum");

		// Access must be forbidden now
		rh.sendHTTPClientCertificate = false;
		checkGeneralAccess(HttpStatus.SC_UNAUTHORIZED, "nagilum", "nagilum");

		// use password instead of hash
		rh.sendHTTPClientCertificate = true;
		addUserWithPassword("nagilum", "correctpassword", HttpStatus.SC_CREATED);

		rh.sendHTTPClientCertificate = false;
		checkGeneralAccess(HttpStatus.SC_UNAUTHORIZED, "nagilum", "wrongpassword");
		checkGeneralAccess(HttpStatus.SC_OK, "nagilum", "correctpassword");

		deleteUser("nagilum");

		// Check unchanged password functionality
		rh.sendHTTPClientCertificate = true;
		
		// new user, password or hash is mandatory
		addUserWithoutPasswordOrHash("nagilum", new String[] { "starfleet" }, HttpStatus.SC_BAD_REQUEST);
		// new user, add hash
		addUserWithHash("nagilum", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
				HttpStatus.SC_CREATED);
		// update user, do not specify hash or password, hash must remain the same
		addUserWithoutPasswordOrHash("nagilum", new String[] { "starfleet" }, HttpStatus.SC_OK);
		// get user, check hash, must be untouched
		response = rh.executeGetRequest("/_searchguard/api/user/nagilum", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertTrue(settings.get("nagilum.hash").equals(""));

		
		// ROLES
		// create index first
		setupStarfleetIndex();

		// wrong datatypes in roles file
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_searchguard/api/user/picard", FileHelper.loadFile("restapi/users_wrong_datatypes.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get("roles").equals("Array expected"));
		rh.sendHTTPClientCertificate = false;

		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_searchguard/api/user/picard", FileHelper.loadFile("restapi/users_wrong_datatypes.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get("roles").equals("Array expected"));
		rh.sendHTTPClientCertificate = false;
		
		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_searchguard/api/user/picard", FileHelper.loadFile("restapi/users_wrong_datatypes2.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get("password").equals("String expected"));
		Assert.assertTrue(settings.get("roles") == null);
		rh.sendHTTPClientCertificate = false;		

		rh.sendHTTPClientCertificate = true;
		response = rh.executePutRequest("/_searchguard/api/user/picard", FileHelper.loadFile("restapi/users_wrong_datatypes3.json"), new Header[0]);
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
		Assert.assertEquals(AbstractConfigurationValidator.ErrorType.WRONG_DATATYPE.getMessage(), settings.get("reason"));
		Assert.assertTrue(settings.get("roles").equals("Array expected"));
		rh.sendHTTPClientCertificate = false;	
		
		// use backendroles when creating user. User picard does not exist in
		// the internal user DB
		// and is also not assigned to any role by username
		addUserWithPassword("picard", "picard", HttpStatus.SC_CREATED);
		// changed in ES5, you now need cluster:monitor/main which pucard does not have
		checkGeneralAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard");

		// check read access to starfleet index and ships type, must fail
		checkReadAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 0);
		
		// overwrite user picard, and give him role "starfleet". This role has READ access only
		addUserWithPassword("picard", "picard", new String[] { "starfleet" }, HttpStatus.SC_OK);
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		checkWriteAccess(HttpStatus.SC_FORBIDDEN, "picard", "picard", "sf", "ships", 1);

		// overwrite user picard, and give him role "starfleet" plus "captains. Now
		// document can be created.
		addUserWithPassword("picard", "picard", new String[] { "starfleet", "captains" }, HttpStatus.SC_OK);
		checkReadAccess(HttpStatus.SC_OK, "picard", "picard", "sf", "ships", 0);
		checkWriteAccess(HttpStatus.SC_CREATED, "picard", "picard", "sf", "ships", 1);

		rh.sendHTTPClientCertificate = true;
		response = rh.executeGetRequest("/_searchguard/api/user/picard", new Header[0]);
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals("", settings.get("picard.hash"));
		roles = settings.getAsList("picard.roles");
		Assert.assertNotNull(roles);
		Assert.assertEquals(2, roles.size());
		Assert.assertTrue(roles.contains("starfleet"));
		Assert.assertTrue(roles.contains("captains"));
		
		addUserWithPassword("$1aAAAAAAAAC", "$1aAAAAAAAAC", HttpStatus.SC_CREATED);
		addUserWithPassword("abc", "abc", HttpStatus.SC_CREATED);
		
		// check tabs in json
        response = rh.executePutRequest("/_searchguard/api/user/userwithtabs", "\t{\"hash\": \t \"123\"\t}  ", new Header[0]);
        Assert.assertEquals(response.getBody(), HttpStatus.SC_CREATED, response.getStatusCode());
	}
	
	@Test
	public void testPasswordRules() throws Exception {

		Settings nodeSettings = 
				Settings.builder()
				.put(ConfigConstants.SEARCHGUARD_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE,"xxx")
				.put(ConfigConstants.SEARCHGUARD_RESTAPI_PASSWORD_VALIDATION_REGEX, 
						"(?=.*[A-Z])(?=.*[^a-zA-Z\\\\d])(?=.*[0-9])(?=.*[a-z]).{8,}")
				.build();
		
		setup(nodeSettings);

		rh.keystore = "restapi/kirk-keystore.jks";
		rh.sendHTTPClientCertificate = true;

		// initial configuration, 5 users
		HttpResponse response = rh
				.executeGetRequest("_searchguard/api/configuration/" + CType.INTERNALUSERS.toLCString());
		Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
		System.out.println(response.getBody());
		Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
		Assert.assertEquals(20, settings.size());

		addUserWithPassword("tooshoort", "123", HttpStatus.SC_BAD_REQUEST);
		addUserWithPassword("tooshoort", "1234567", HttpStatus.SC_BAD_REQUEST);
		addUserWithPassword("tooshoort", "1Aa%", HttpStatus.SC_BAD_REQUEST);
		addUserWithPassword("no-nonnumeric", "123456789", HttpStatus.SC_BAD_REQUEST);
		addUserWithPassword("no-uppercase", "a123456789", HttpStatus.SC_BAD_REQUEST);
		addUserWithPassword("no-lowercase", "A123456789", HttpStatus.SC_BAD_REQUEST);
		addUserWithPassword("ok1", "a%A123456789", HttpStatus.SC_CREATED);
		addUserWithPassword("ok2", "$aA123456789", HttpStatus.SC_CREATED);
		addUserWithPassword("ok3", "$Aa123456789", HttpStatus.SC_CREATED);
		addUserWithPassword("ok4", "$1aAAAAAAAAA", HttpStatus.SC_CREATED);
		
        response = rh.executePatchRequest("/_searchguard/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/ok4\", \"value\": {\"password\": \"bla\", \"roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        
        response = rh.executePatchRequest("/_searchguard/api/internalusers", "[{ \"op\": \"replace\", \"path\": \"/ok4\", \"value\": {\"password\": \"bla\", \"roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        
        addUserWithPassword("ok4", "123", HttpStatus.SC_BAD_REQUEST);
        
        response = rh.executePatchRequest("/_searchguard/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/ok4\", \"value\": {\"password\": \"$1aAAAAAAAAB\", \"roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        
        addUserWithPassword("ok4", "$1aAAAAAAAAC", HttpStatus.SC_OK);
		
        //its not allowed to use the username as password (case insensitive)
        response = rh.executePatchRequest("/_searchguard/api/internalusers", "[{ \"op\": \"add\", \"path\": \"/$1aAAAAAAAAB\", \"value\": {\"password\": \"$1aAAAAAAAAB\", \"roles\": [\"vulcan\"] } }]", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        addUserWithPassword("$1aAAAAAAAAC", "$1aAAAAAAAAC", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword("$1aAAAAAAAac", "$1aAAAAAAAAC", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword(URLEncoder.encode("$1aAAAAAAAac%", "UTF-8"), "$1aAAAAAAAAC%", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword(URLEncoder.encode("$1aAAAAAAAac%!=\"/\\;: test&~@^", "UTF-8"), "$1aAAAAAAAac%!=\\\"/\\\\;: test&~@^", HttpStatus.SC_BAD_REQUEST);
        addUserWithPassword(URLEncoder.encode("$1aAAAAAAAac%!=\"/\\;: test&", "UTF-8"), "$1aAAAAAAAac%!=\\\"/\\\\;: test&123", HttpStatus.SC_CREATED);

        response = rh.executeGetRequest("/_searchguard/api/internalusers/nothinghthere?pretty", new Header[0]);
        Assert.assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("NOT_FOUND"));
        
        String patchPayload="[ "+
            "{ \"op\": \"add\", \"path\": \"/testuser1\",  \"value\": { \"password\": \"$aA123456789\", \"roles\": [\"testrole1\"] } },"+
            "{ \"op\": \"add\", \"path\": \"/testuser2\",  \"value\": { \"password\": \"testpassword2\", \"roles\": [\"testrole2\"] } }"+
         "]";
        
        response = rh.executePatchRequest("/_searchguard/api/internalusers", patchPayload, new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        Assert.assertTrue(response.getBody().contains("error"));
        Assert.assertTrue(response.getBody().contains("xxx"));
	}
	
	@Test
    public void testUserApiWithDots() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;

        // initial configuration, 5 users
        HttpResponse response = rh
                .executeGetRequest("_searchguard/api/configuration/" + CType.INTERNALUSERS.toLCString());
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        Settings settings = Settings.builder().loadFromSource(response.getBody(), XContentType.JSON).build();
        Assert.assertEquals(20, settings.size());
        
        addDotUserUserWithHash("my.dotuser0", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_BAD_REQUEST, false);
        
        addDotUserWithPassword("my.dot.user0", "12345678",
                HttpStatus.SC_BAD_REQUEST, false);
        
        addDotUserUserWithHash("my.dotuser1", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_CREATED, true);
        
        addDotUserWithPassword("my.dot.user2", "12345678",
                HttpStatus.SC_CREATED, true);

	}
	
	@Test
    public void testUserApiNoPasswordChange() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendHTTPClientCertificate = true;

        // initial configuration, 5 users
        HttpResponse response;
        
        addUserWithHash("user1", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_CREATED);
        
        response = rh.executePutRequest("/_searchguard/api/user/user1", "{\"hash\":\"$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m\",\"password\":\"\",\"roles\":[\"admin\",\"rolea\"]}");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        
        response = rh.executeGetRequest("/_searchguard/api/user/user1");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        
        addUserWithHash("user2", "$2a$12$n5nubfWATfQjSYHiWtUyeOxMIxFInUHOAx8VMmGmxFNPGpaBmeB.m",
                HttpStatus.SC_CREATED);
        
        response = rh.executePutRequest("/_searchguard/api/user/user2", "{\"password\":\"\",\"roles\":[\"admin\",\"rolex\"]}");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        
        response = rh.executeGetRequest("/_searchguard/api/user/user2");
        Assert.assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

}
