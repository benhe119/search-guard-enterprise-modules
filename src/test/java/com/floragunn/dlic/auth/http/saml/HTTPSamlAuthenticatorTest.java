package com.floragunn.dlic.auth.http.saml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;

import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestResponse;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.saml.saml2.core.NameIDType;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.util.FakeRestRequest;
import com.google.common.collect.ImmutableMap;

public class HTTPSamlAuthenticatorTest {
    protected static MockSamlIdpServer mockSamlIdpServer;
    private static final Pattern WWW_AUTHENTICATE_PATTERN = Pattern
            .compile("([^\\s]+)\\s*([^\\s=]+)=\"([^\"]+)\"\\s*([^\\s=]+)=\"([^\"]+)\"\\s*([^\\s=]+)=\"([^\"]+)\"\\s*");

    private static X509Certificate spSigningCertificate;
    private static PrivateKey spSigningPrivateKey;

    @BeforeClass
    public static void setUp() throws Exception {
        mockSamlIdpServer = new MockSamlIdpServer();
        initSpSigningKeys();
    }

    @AfterClass
    public static void tearDown() {
        if (mockSamlIdpServer != null) {
            try {
                mockSamlIdpServer.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Test
    public void basicTest() throws Exception {
        Settings settings = Settings.builder().put("idp.metadata_url", mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").build();

        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = new ObjectMapper().readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
    }

    @Test
    public void wrongCertTest() throws Exception {
        Settings settings = Settings.builder().put("idp.metadata_url", mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").build();

        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        mockSamlIdpServer.loadSigningKeys("saml/spock-keystore.jks", "spock");

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        Assert.assertEquals(401, tokenRestChannel.response.status().getStatus());
    }

    @Test
    public void noSignatureTest() throws Exception {
        Settings settings = Settings.builder().put("idp.metadata_url", mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").build();

        mockSamlIdpServer.setSignResponses(false);
        mockSamlIdpServer.setAuthenticateUser("horst");

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        Assert.assertEquals(401, tokenRestChannel.response.status().getStatus());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void rolesTest() throws Exception {
        Settings settings = Settings.builder().put("idp.metadata_url", mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").build();

        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setAuthenticateUserRoles(Arrays.asList("a", "b"));

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = new ObjectMapper().readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
        Assert.assertArrayEquals(new String[] { "a", "b" },
                ((List<String>) jwt.getClaim("roles")).toArray(new String[0]));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void commaSeparatedRolesTest() throws Exception {
        Settings settings = Settings.builder().put("idp.metadata_url", mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("roles_seperator", ",").build();

        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUserRoles(Arrays.asList("a,b"));

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = new ObjectMapper().readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
        Assert.assertArrayEquals(new String[] { "a", "b" },
                ((List<String>) jwt.getClaim("roles")).toArray(new String[0]));
    }

    @Test
    public void basicLogoutTest() throws Exception {
        Settings settings = Settings.builder().put("idp.metadata_url", mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles")
                .put("sp.signature_private_key", Base64.getEncoder().encodeToString(spSigningPrivateKey.getEncoded()))
                .build();

        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setSpSignatureCertificate(spSigningCertificate);

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthCredentials authCredentials = new AuthCredentials("horst");
        authCredentials.addAttribute("attr.jwt.sub", "horst");
        authCredentials.addAttribute("attr.jwt.saml_nif", NameIDType.UNSPECIFIED);
        authCredentials.addAttribute("attr.jwt.saml_si", "si123");

        String logoutUrl = samlAuthenticator.buildLogoutUrl(authCredentials);

        mockSamlIdpServer.handleSloGetRequestURI(logoutUrl);

    }

    private AuthenticateHeaders getAutenticateHeaders(HTTPSamlAuthenticator samlAuthenticator) {
        RestRequest restRequest = new FakeRestRequest(ImmutableMap.of(), new HashMap<String, String>());
        TestRestChannel restChannel = new TestRestChannel(restRequest);

        samlAuthenticator.reRequestAuthentication(restChannel, null);

        List<String> wwwAuthenticateHeaders = restChannel.response.getHeaders().get("WWW-Authenticate");

        Assert.assertNotNull(wwwAuthenticateHeaders);
        Assert.assertEquals("More than one WWW-Authenticate header: " + wwwAuthenticateHeaders, 1,
                wwwAuthenticateHeaders.size());

        String wwwAuthenticateHeader = wwwAuthenticateHeaders.get(0);

        Matcher wwwAuthenticateHeaderMatcher = WWW_AUTHENTICATE_PATTERN.matcher(wwwAuthenticateHeader);

        if (!wwwAuthenticateHeaderMatcher.matches()) {
            Assert.fail("Invalid WWW-Authenticate header: " + wwwAuthenticateHeader);
        }

        Assert.assertEquals("X-SG-IdP", wwwAuthenticateHeaderMatcher.group(1));
        Assert.assertEquals("location", wwwAuthenticateHeaderMatcher.group(4));
        Assert.assertEquals("requestId", wwwAuthenticateHeaderMatcher.group(6));

        String location = wwwAuthenticateHeaderMatcher.group(5);
        String requestId = wwwAuthenticateHeaderMatcher.group(7);

        return new AuthenticateHeaders(location, requestId);
    }

    private RestRequest buildTokenExchangeRestRequest(String encodedSamlResponse,
            AuthenticateHeaders authenticateHeaders) {
        String authtokenPostJson = "{\"SAMLResponse\": \"" + encodedSamlResponse + "\", \"RequestId\": \""
                + authenticateHeaders.requestId + "\"}";

        return new FakeRestRequest.Builder().withPath("/_searchguard/api/authtoken").withMethod(Method.POST)
                .withContent(new BytesArray(authtokenPostJson))
                .withHeaders(ImmutableMap.of("Content-Type", "application/json")).build();
    }

    private static void initSpSigningKeys() {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

            KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream keyStream = new FileInputStream(
                    FileHelper.getAbsoluteFilePathFromClassPath("saml/spock-keystore.jks").toFile());

            keyStore.load(keyStream, "changeit".toCharArray());
            kmf.init(keyStore, "changeit".toCharArray());

            spSigningCertificate = (X509Certificate) keyStore.getCertificate("spock");

            spSigningPrivateKey = (PrivateKey) keyStore.getKey("spock", "changeit".toCharArray());

        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException
                | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    static class TestRestChannel implements RestChannel {

        final RestRequest restRequest;
        RestResponse response;

        TestRestChannel(RestRequest restRequest) {
            this.restRequest = restRequest;
        }

        @Override
        public XContentBuilder newBuilder() throws IOException {
            return null;
        }

        @Override
        public XContentBuilder newErrorBuilder() throws IOException {
            return null;
        }

        @Override
        public XContentBuilder newBuilder(XContentType xContentType, boolean useFiltering) throws IOException {
            return null;
        }

        @Override
        public BytesStreamOutput bytesOutput() {
            return null;
        }

        @Override
        public RestRequest request() {
            return restRequest;
        }

        @Override
        public boolean detailedErrorsEnabled() {
            return false;
        }

        @Override
        public void sendResponse(RestResponse response) {
            this.response = response;

        }

    }

    static class AuthenticateHeaders {
        final String location;
        final String requestId;

        AuthenticateHeaders(String location, String requestId) {
            this.location = location;
            this.requestId = requestId;
        }
    }
}
