/*
 * Copyright 2016-2018 by floragunn GmbH - All rights reserved
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

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Node;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.XContentType;

import com.floragunn.dlic.util.SettingsBasedSSLConfigurator.SSLConfig;
import com.google.common.collect.Lists;

public class HttpClient implements Closeable {

    public static class HttpClientBuilder {

        private SSLConfig sslConfig;
        private String basicCredentials;
        private final String[] servers;

        private HttpClientBuilder(final String... servers) {
            super();
            this.servers = Objects.requireNonNull(servers);
            if (this.servers.length == 0) {
                throw new IllegalArgumentException();
            }
        }

        public HttpClientBuilder enableSsl(SSLConfig sslConfig) {
            this.sslConfig = sslConfig;
            return this;
        }

        public HttpClientBuilder setBasicCredentials(final String username, final String password) {
            basicCredentials = encodeBasicHeader(Objects.requireNonNull(username), Objects.requireNonNull(password));
            return this;
        }

        public HttpClient build() throws Exception {
            return new HttpClient(sslConfig, basicCredentials, servers);
        }
        
        private static String encodeBasicHeader(final String username, final String password) {
            return Base64.encodeBase64String((username + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8));
        }

    }

    public static HttpClientBuilder builder(final String... servers) {
        return new HttpClientBuilder(servers);
    }

    private final Logger log = LogManager.getLogger(this.getClass());
    private SSLConfig sslConfig;
    private RestHighLevelClient rclient;
    private String basicCredentials;
    

    private HttpClient(final SSLConfig sslConfig, final String basicCredentials, final String... servers) {
        super();
        this.sslConfig = sslConfig;
        this.basicCredentials = basicCredentials;

        HttpHost[] hosts = Arrays.stream(servers)
                .map(s->s.split(":"))
                .map(s->new HttpHost(s[0], Integer.parseInt(s[1]),sslConfig!=null?"https":"http"))
                .collect(Collectors.toList()).toArray(new HttpHost[0]);
                
        
        RestClientBuilder builder = RestClient.builder(hosts);
        //builder.setMaxRetryTimeoutMillis(10000);

        builder.setFailureListener(new RestClient.FailureListener() {
            @Override
            public void onFailure(Node node) {

            }
            
        });

        builder.setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
            @Override
            public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
                try {
                    return asyncClientBuilder(httpClientBuilder);
                } catch (Exception e) {
                    log.error("Unable to build http client",e);
                    throw new RuntimeException(e);
                }
            }
        });
        
        rclient = new RestHighLevelClient(builder);
    }

    public boolean index(final String content, final String index, final String type, final boolean refresh) {

            try {

                final IndexRequest ir = type==null?new IndexRequest(index):new IndexRequest(index, type);
                
                final IndexResponse response = rclient.index(ir
                              .setRefreshPolicy(refresh?RefreshPolicy.IMMEDIATE:RefreshPolicy.NONE)
                              .source(content, XContentType.JSON), RequestOptions.DEFAULT);

                return response.getShardInfo().getSuccessful() > 0 && response.getShardInfo().getFailed() == 0;
                
            } catch (Exception e) {
                log.error(e.toString(),e);
                return false;
            }
    }

    private final HttpAsyncClientBuilder asyncClientBuilder(HttpAsyncClientBuilder httpClientBuilder) 
            throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {

        // basic auth
        // pki auth

        if (sslConfig != null) {
            httpClientBuilder.setSSLStrategy(sslConfig.toSSLIOSessionStrategy());
        }

        if (basicCredentials != null) {
            httpClientBuilder.setDefaultHeaders(Lists.newArrayList(new BasicHeader(HttpHeaders.AUTHORIZATION, "Basic " + basicCredentials)));
        }
        
        // TODO: set a timeout until we have a proper way to deal with back pressure
        int timeout = 5;
        
        RequestConfig config = RequestConfig.custom()
          .setConnectTimeout(timeout * 1000)
          .setConnectionRequestTimeout(timeout * 1000)
          .setSocketTimeout(timeout * 1000).build();
        
        httpClientBuilder.setDefaultRequestConfig(config);
        
        return httpClientBuilder;
        
    }

    @Override
    public void close() throws IOException {
        if (rclient != null) {
            rclient.close();
        }
    }
}
