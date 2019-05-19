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

package com.floragunn.searchguard.httpclient;

import java.nio.file.Paths;

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.dlic.util.SettingsBasedSSLConfigurator;
import com.floragunn.dlic.util.SettingsBasedSSLConfigurator.SSLConfig;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.file.FileHelper;

public class HttpClientTest extends SingleClusterTest {

    @Override
    protected String getResourceFolder() {
        return "auditlog";
    }
    
    @Test
    public void testPlainConnection() throws Exception {
        
        final Settings settings = Settings.builder()
                .put("searchguard.ssl.http.enabled", false)
                .build();

        setup(Settings.EMPTY, new DynamicSgConfig(), settings);
        
        Thread.sleep(1000);

        try(final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
        try(final HttpClient httpClient = HttpClient.builder("unknownhost:6654")
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
        Settings sslSettings = Settings.builder()
               .put("path.home", ".")
               .put(SettingsBasedSSLConfigurator.ENABLE_SSL, true)
               .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, 
                       FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore"+(!utFips()?".jks":".BCFKS")))
               .build();
        
        
        SSLConfig sslConfig = new SettingsBasedSSLConfigurator(sslSettings, Paths.get(""), "").buildSSLConfig();
        
        Assert.assertNotNull(sslConfig);
        
        try(final HttpClient httpClient = HttpClient.builder("unknownhost:6654", clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .enableSsl(sslConfig)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
        try(final HttpClient httpClient = HttpClient.builder("unknownhost:6654", clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
    }
    
    @Test
    public void testSslConnection() throws Exception {

        final Settings settings = Settings.builder()
                .put("searchguard.ssl.http.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore"+(!utFips()?".jks":".BCFKS")))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore"+(!utFips()?".jks":".BCFKS")))
                .build();

        setup(Settings.EMPTY, new DynamicSgConfig(), settings);
        
        Thread.sleep(1000);
        
        Settings sslSettings = Settings.builder()
                .put("path.home", ".")
                .put(SettingsBasedSSLConfigurator.ENABLE_SSL, true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, 
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore"+(!utFips()?".jks":".BCFKS")))
                .build();
         
         
         SSLConfig sslConfig = new SettingsBasedSSLConfigurator(sslSettings, Paths.get(""), "").buildSSLConfig();
         
         Assert.assertNotNull(sslConfig);

        try(final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .enableSsl(sslConfig)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
        try(final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
    }
    
    @Test
    public void testSslConnectionPKIAuth() throws Exception {
        
        final Settings settings = Settings.builder()
                .put("searchguard.ssl.http.enabled", true)
                .put("searchguard.ssl.http.clientauth_mode", "REQUIRE")
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore"+(!utFips()?".jks":".BCFKS")))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore"+(!utFips()?".jks":".BCFKS")))
                .build();

        setup(Settings.EMPTY, new DynamicSgConfig(), settings);
        
        Thread.sleep(1000);
        
        Settings sslSettings = Settings.builder()
                .put("path.home", ".")
                .put(SettingsBasedSSLConfigurator.ENABLE_SSL, true)
                .put(SettingsBasedSSLConfigurator.ENABLE_SSL_CLIENT_AUTH, true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, 
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore"+(!utFips()?".jks":".BCFKS")))
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, 
                        FileHelper.getAbsoluteFilePathFromClassPath("auditlog/spock-keystore"+(!utFips()?".jks":".BCFKS")))
                .build();
         
         
         SSLConfig sslConfig = new SettingsBasedSSLConfigurator(sslSettings, Paths.get(""), "").buildSSLConfig();
         
         Assert.assertNotNull(sslConfig);

        try(final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .enableSsl(sslConfig)
                .build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }
        
    }
}
