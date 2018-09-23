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

package com.floragunn.dlic.auth.ldap;

import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.rest.RestHelper;

public class LdapBackendIntegTest extends SingleClusterTest {

    private static EmbeddedLDAPServer ldapServer = null;
    
    @BeforeClass
    public static void startLdapServer() throws Exception {
        ldapServer = new EmbeddedLDAPServer();
        ldapServer.start();
        ldapServer.applyLdif("base.ldif");
    }
    
    @Override
    protected String getResourceFolder() {
        return "ldap";
    }

    @Test
    public void testIntegLdapAuthenticationSSL() throws Exception {
        setup();
        final RestHelper rh = nonSslRestHelper();
        Assert.assertEquals(HttpStatus.SC_OK, rh.executeGetRequest("", encodeBasicHeader("jacksonm", "secret")).getStatusCode());
    }
    
    
    
    @AfterClass
    public static void tearDownLdap() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }

    }
}
