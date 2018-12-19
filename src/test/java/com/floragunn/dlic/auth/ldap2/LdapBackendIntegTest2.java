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

package com.floragunn.dlic.auth.ldap2;

import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer;
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;

public class LdapBackendIntegTest2 extends SingleClusterTest {

    private static EmbeddedLDAPServer ldapServer = null;
    
    private static int ldapPort;
    private static int ldapsPort;
    
    @BeforeClass
    public static void startLdapServer() throws Exception {
        ldapServer = new EmbeddedLDAPServer();
        ldapServer.start();
        ldapServer.applyLdif("base.ldif");
        ldapPort = ldapServer.getLdapPort();
        ldapsPort = ldapServer.getLdapsPort();
    }
    
    @Override
    protected String getResourceFolder() {
        return "ldap";
    }

    @Test
    public void testIntegLdapAuthenticationSSL() throws Exception {
        String sgConfigAsYamlString = FileHelper.loadFile("ldap/sg_config_ldap2.yml");
        sgConfigAsYamlString = sgConfigAsYamlString.replace("${ldapsPort}", String.valueOf(ldapsPort));
        System.out.println(sgConfigAsYamlString);
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfigAsYamlString(sgConfigAsYamlString), Settings.EMPTY);
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
