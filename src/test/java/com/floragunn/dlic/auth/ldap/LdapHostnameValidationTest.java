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

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.elasticsearch.ExceptionsHelper;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import com.floragunn.dlic.auth.ldap.srv.EmbeddedLDAPServer;
import com.floragunn.searchguard.crypto.CryptoManagerFactory;
import com.floragunn.searchguard.support.SgUtils;
import com.floragunn.searchguard.test.AbstractSGUnitTest;

public class LdapHostnameValidationTest extends AbstractSGUnitTest {

    
    private static EmbeddedLDAPServer ldapServer = null;
    private static int ldapsPort;
    
    @BeforeClass
    public static void startLdapServer() throws Exception {
        ldapServer = new EmbeddedLDAPServer(false);
        ldapServer.start();
        ldapServer.applyLdif("base.ldif");
        ldapsPort = ldapServer.getLdapsPort();
    }
    
    @AfterClass
    public static void tearDown() throws Exception {

        if (ldapServer != null) {
            ldapServer.stop();
        }
    }
    
    public static int exec(Class klass, String... args) throws IOException, InterruptedException {
        String javaHome = System.getProperty("java.home");
        String javaBin = javaHome + File.separator + "bin" + File.separator + "java";
        String classpath = System.getProperty("java.class.path");
        String className = klass.getName();
        
        List<String> args0 = new ArrayList<>();
        args0.addAll(Arrays.asList(javaBin, "-cp", classpath, className));
        args0.addAll(Arrays.asList(args));

        FileUtils.deleteQuietly(new File("/tmp/javaout.txt"));
        ProcessBuilder builder = new ProcessBuilder(args0);
        builder.redirectOutput(new File("/tmp/javaout.txt"));
        builder.redirectError(Redirect.INHERIT);
        builder.redirectInput(Redirect.INHERIT);
        
        Process process = builder.start();
        process.waitFor();
        return process.exitValue();
    }

    @Test
    public void testHostnameVerificationFipsDEIFalseVerifyFalse() {
        Assume.assumeTrue(CryptoManagerFactory.isFipsEnabled());
        
        if(SgUtils.isJndiHostnameValidationEnabledByDefault() == Boolean.TRUE) {
            //must fail on Java >= 181 because DisableEndpointIdentification was not defined and FIPS is active
            testHostnameVerification(false, false, "No subject alternative DNS name matching localhost found");
        } else {
            //must not fail on Java < 181 because no jndi hostname validation by default and FIPS is active
            testHostnameVerification(false, false, null);
        }
    }
    @Test
    public void testHostnameVerificationFipsDEIFalseVerifyTrue() {
        Assume.assumeTrue(CryptoManagerFactory.isFipsEnabled());
        
        if(SgUtils.isJndiHostnameValidationEnabledByDefault() == Boolean.TRUE) {
            //must fail on Java >= 181 because DisableEndpointIdentification was not defined and FIPS is active
            testHostnameVerification(false, true, "No subject alternative DNS name matching localhost found");
        } else {
            //must not fail on Java < 181 because no jndi hostname validation by default and FIPS is active
            testHostnameVerification(false, true, null);
        }
    }
    @Test
    public void testHostnameVerificationFipsDEITrueVerifyTrue() {
        Assume.assumeTrue(CryptoManagerFactory.isFipsEnabled());
        
        testHostnameVerification(true, true, null);
    }
    @Test
    public void testHostnameVerificationFipsDEITrueVerifyFalse() {
        Assume.assumeTrue(CryptoManagerFactory.isFipsEnabled());
        
        testHostnameVerification(true, false, null);
    }
    
    @Test
    public void testHostnameVerificationDEIFalseVerifyFalse() {
        Assume.assumeFalse(CryptoManagerFactory.isFipsEnabled());
        
        if(SgUtils.isJndiHostnameValidationEnabledByDefault() == Boolean.TRUE) {
            //must fail on Java >= 181 because DisableEndpointIdentification was not defined
            testHostnameVerification(false, false, "No subject alternative DNS name matching localhost found");
        } else {
            //must not fail on Java < 181 because no jndi hostname validation by default and no ldaptive validation
            testHostnameVerification(false, false, null);
        }
    }
    @Test
    public void testHostnameVerificationDEIFalseVerifyTrue() {
        Assume.assumeFalse(CryptoManagerFactory.isFipsEnabled());
        
        if(SgUtils.isJndiHostnameValidationEnabledByDefault() == Boolean.TRUE) {
            testHostnameVerification(false, true, "does not match the hostname");
        } else {
            //must fail on Java < 181 because no jndi hostname validation by default  but ldaptive validates
            testHostnameVerification(false, true, "does not match the hostname");
        }
    }
    
    @Test
    public void testHostnameVerificationDEItrueVerifyTrue() {
        Assume.assumeFalse(CryptoManagerFactory.isFipsEnabled());
        
        //must fail on Java < 181 because no jndi hostname validation by default  but ldaptive validates
        testHostnameVerification(true, true, "does not match the hostname");
    }
    @Test
    public void testHostnameVerificationDEItrueVerifyFalse() {
        Assume.assumeFalse(CryptoManagerFactory.isFipsEnabled());
        
        //must not fail on Java < 181 because no jndi hostname validation by default and no ldaptive validation
        testHostnameVerification(true, false, null);
    }
    
    //@Test
    private void testHostnameVerification() {

        //Test in different classloader
        
        
        //we need to test all tests with defineDisableEndpointIdentification = false first
        //once enabled you can not clear the property because of reasons how it is internally used by jndi
       
        if(CryptoManagerFactory.isFipsEnabled()) {
            //with FIPS we only rely on JNDI hostname verification
            //so maybe we should make 181 the default minimum version, or can we force jndi to verify?
            
            if(SgUtils.isJndiHostnameValidationEnabledByDefault() == Boolean.TRUE) {
                //must fail on Java >= 181 because DisableEndpointIdentification was not defined and FIPS is active
                testHostnameVerification(false, false, "No subject alternative DNS name matching localhost found");
                //must fail on Java >= 181 because DisableEndpointIdentification was not defined and FIPS is active
                testHostnameVerification(false, true, "No subject alternative DNS name matching localhost found");
            } else {
                //must not fail on Java < 181 because no jndi hostname validation by default and FIPS is active
                testHostnameVerification(false, false, null);
                //must not fail on Java < 181 because no jndi hostname validation by default and FIPS is active
                testHostnameVerification(false, true, null);
            }
        } else {
            
            if(SgUtils.isJndiHostnameValidationEnabledByDefault() == Boolean.TRUE) {
                //must fail on Java >= 181 because DisableEndpointIdentification was not defined
                testHostnameVerification(false, false, "No subject alternative DNS name matching localhost found");
                //must fail on Java >= 181 because DisableEndpointIdentification was not defined
                testHostnameVerification(false, true, "No subject alternative DNS name matching localhost found");
            } else {
                //must not fail on Java < 181 because no jndi hostname validation by default and no ldaptive validation
                testHostnameVerification(false, false, null);
                //must fail on Java < 181 because no jndi hostname validation by default  but ldaptive validates
                testHostnameVerification(false, true, "No subject alternative DNS name matching localhost found");
            }
        }
        
        //now we define DisableEndpointIdentification and so jndi hostname validation is turned off
        
        if(CryptoManagerFactory.isFipsEnabled()) {
            //with FIPS we only rely on JNDI hostname verification
            //so maybe we should make 181 the default minimum version, or can we force jndi to verify?
            //must not fail on Java < 181 because no jndi hostname validation by default and no ldaptive validation
            testHostnameVerification(true, false, null);
            //must not fail on Java < 181 because no jndi hostname validation by default and no ldaptive validation because of fips
            testHostnameVerification(true, true, null);
            
        } else {

            //must not fail on Java < 181 because no jndi hostname validation by default and no ldaptive validation
            testHostnameVerification(true, false, null);
            //must fail on Java < 181 because no jndi hostname validation by default  but ldaptive validates
            testHostnameVerification(true, true, "No subject alternative DNS name matching localhost found");
            
        }
    }
    
    protected void testHostnameVerification(boolean defineDisableEndpointIdentification, boolean verifyHostnames, String checkForInStacktrace) {
        
        if(checkForInStacktrace != null) {

                try {
                    //boolean defineDisableEndpointIdentification, 
                    //boolean verifyHostnames, 
                    //boolean fips, 
                    //int ldapsPort
                    int exit = exec(LdapBackendHostnameValidationTest.class, String.valueOf(defineDisableEndpointIdentification), String.valueOf(verifyHostnames), String.valueOf(CryptoManagerFactory.isFipsEnabled()), String.valueOf(ldapsPort));
                    Assert.assertNotEquals(0, exit);
                    try {
                        String content = FileUtils.readFileToString(new File("/tmp/javaout.txt"), StandardCharsets.ISO_8859_1);
                        Assert.assertTrue(content,content.contains(checkForInStacktrace));
                    } catch (IOException e1) {
                        e1.printStackTrace();
                        Assert.fail(e1.toString());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    Assert.fail(e.toString());
                }
            
        } else {
            try {
                try {
                    //boolean defineDisableEndpointIdentification, 
                    //boolean verifyHostnames, 
                    //boolean fips, 
                    //int ldapsPort
                    int exit = exec(LdapBackendHostnameValidationTest.class, String.valueOf(defineDisableEndpointIdentification), String.valueOf(verifyHostnames), String.valueOf(CryptoManagerFactory.isFipsEnabled()), String.valueOf(ldapsPort));
                    Assert.assertEquals(0, exit);
                } catch (Throwable e) {
                    e.printStackTrace();
                    Assert.fail(e.toString());
                }
            } catch (Exception e) {
                Assert.fail("No Exception expected but got "+ExceptionsHelper.stackTrace(e));
            }
        }

    }

}
