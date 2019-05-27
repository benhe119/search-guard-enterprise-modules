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

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.TreeSet;

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;

import com.floragunn.dlic.auth.ldap.LdapUser;
import com.floragunn.dlic.auth.ldap.util.ConfigConstants;
import com.floragunn.searchguard.crypto.CryptoManagerFactory;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.user.AuthCredentials;

import io.netty.handler.ssl.OpenSsl;

public class LdapBackendHostnameValidationTest2 {
    
    public static void main(String[] args) throws Throwable {
        try {
            System.out.println("LdapBackendHostnameValidationTest2: "+Arrays.toString(args));
            testHostnameVerification(Boolean.parseBoolean(args[0]),Boolean.parseBoolean(args[1]),Boolean.parseBoolean(args[2]),Integer.parseInt(args[3]));
        } catch (Throwable e) {
            e.printStackTrace(System.out);
            throw e;
        }
    }

    public static void testHostnameVerification(boolean defineDisableEndpointIdentification, 
            boolean verifyHostnames, 
            boolean fips, 
            int ldapsPort) throws Throwable {
        
        if(defineDisableEndpointIdentification) {
            System.setProperty("com.sun.jndi.ldap.object.disableEndpointIdentification", "true"); //must be true
        }

        
        if(System.getSecurityManager() == null) {
            //we need a security in case we test with FIPS
            Policy.setPolicy(new Policy() {
    
                @Override
                public boolean implies(ProtectionDomain domain, Permission permission) {
                    if(permission.getClass().getName().equals("org.bouncycastle.crypto.CryptoServicesPermission")) {
                        if(permission.getActions().equals("[unapprovedModeEnabled]")) {
                            //System.out.println(permission);
                            return false;
                        }
                    }
                    return true;
                }
                
            });
    
            System.setSecurityManager(new SecurityManager());
            System.out.println("Security Manager installed (ldap jvm)");
        }

        CryptoManagerFactory.initialize(fips);
        
        
        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + " "
                + System.getProperty("os.version"));
        System.out.println(
                "Java Version: " + System.getProperty("java.version") + " " + System.getProperty("java.vendor"));
        System.out.println("JVM Impl.: " + System.getProperty("java.vm.version") + " "
                + System.getProperty("java.vm.vendor") + " " + System.getProperty("java.vm.name"));
        System.out.println("Open SSL loadable: " + OpenSsl.isAvailable());
        System.out.println("Open SSL available: " + CryptoManagerFactory.getInstance().isOpenSslAvailable());
        System.out.println("Open SSL version: " + OpenSsl.versionString());

        final Settings settings = Settings.builder()
                .putList(ConfigConstants.LDAP_HOSTS, "localhost:" + ldapsPort)
                .put(ConfigConstants.LDAP_AUTHC_USERSEARCH, "(uid={0})")
                .put(ConfigConstants.LDAP_AUTHC_USERBASE, "ou=people,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLEBASE, "ou=groups,o=TEST")
                .put(ConfigConstants.LDAP_AUTHZ_ROLENAME, "cn")
                .put(ConfigConstants.LDAP_AUTHZ_ROLESEARCH, "(uniqueMember={0})")

                .put(ConfigConstants.LDAPS_ENABLE_SSL, true)
                .put(ConfigConstants.LDAPS_PEMTRUSTEDCAS_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ldap/root-ca.pem").toFile().getName())
                .put(ConfigConstants.LDAPS_PEMCERT_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ldap/node-0.crt.pem").toFile().getName())
                .put(ConfigConstants.LDAPS_PEMKEY_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ldap/node-0.key.pem").toFile().getName())
                .put(ConfigConstants.LDAPS_VERIFY_HOSTNAMES, verifyHostnames)
                .put(ConfigConstants.LDAPS_ENABLE_SSL_CLIENT_AUTH, false)
                .put("path.home",".")
                .build();
        
        final Path configPath = FileHelper.getAbsoluteFilePathFromClassPath("ldap/root-ca.pem").getParent();

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend2(settings, configPath).authenticate(new AuthCredentials("jacksonm", "secret"
                .getBytes(StandardCharsets.UTF_8)));

        new LDAPAuthorizationBackend2(settings, configPath).fillRoles(user, null);

        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals("ceo", new ArrayList(new TreeSet(user.getRoles())).get(0));
        Assert.assertEquals(user.getName(), user.getUserEntry().getDn());
    }
}
