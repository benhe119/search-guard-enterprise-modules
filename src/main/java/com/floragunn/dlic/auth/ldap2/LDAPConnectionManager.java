package com.floragunn.dlic.auth.ldap2;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLSocketFactory;

import org.elasticsearch.common.settings.Settings;

import com.floragunn.dlic.auth.ldap.util.ConfigConstants;
import com.floragunn.dlic.util.SettingsBasedSSLConfigurator;
import com.floragunn.dlic.util.SettingsBasedSSLConfigurator.SSLConfig;
import com.floragunn.dlic.util.SettingsBasedSSLConfigurator.SSLConfigException;
import com.google.common.primitives.Ints;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RoundRobinServerSet;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.StartTLSPostConnectProcessor;

public final class LDAPConnectionManager implements Closeable{

    private final LDAPConnectionPool pool;
    private final SSLConfig sslConfig;
    private final LDAPUserSearcher userSearcher;
    private final Settings settings;

    
    public LDAPConnectionManager(Settings settings, Path configPath) throws LDAPException, SSLConfigException {
        
        this.sslConfig = new SettingsBasedSSLConfigurator(settings, configPath, "").buildSSLConfig();
        this.settings = settings;
        
        /*
        
        NOT supported yet 
        Can imho be done with GetEntryLDAPConnectionPoolHealthCheck
        in combination with AggregateLDAPConnectionPoolHealthCheck and 
        PruneUnneededConnectionsLDAPConnectionPoolHealthCheck
        
        this.settings.getAsBoolean("validation.enabled", false)) {
        this.settings.getAsBoolean("validation.on_checkin", false));
        this.settings.getAsBoolean("validation.on_checkout", false));
        this.settings.getAsBoolean("validation.periodically", true));
        this.settings.getAsLong("validation.period", 30l)));
        this.settings.getAsLong("validation.timeout", 5l)));
        this.settings.get("validation.strategy", "search");
        this.settings.get("validation.compare.dn", ""),
        this.settings.get("validation.compare.attribute", "objectClass"),
        this.settings.get("validation.compare.value", "top"))));
        this.settings.get("validation.search.base_dn", ""));
        this.settings.get("validation.search.filter", "(objectClass=*)")));
        this.settings.getAsLong("pruning.period", 5l)),
        this.settings.getAsLong("pruning.idleTime", 10l))));
        LDAP_CONNECTION_STRATEGY not supported, only roundrobin currently
        */

        List<String> ldapStrings = this.settings.getAsList(ConfigConstants.LDAP_HOSTS,
                Collections.singletonList("localhost"));
        
        String bindDn = settings.get(ConfigConstants.LDAP_BIND_DN, null);
        String password = settings.get(ConfigConstants.LDAP_PASSWORD, null);

        if (password != null && password.length() == 0) {
            password = null;
        }
        
        final BindRequest bindRequest;
        if (bindDn != null && password != null && password.length() > 0) {
            bindRequest = new SimpleBindRequest(bindDn, password);
        } else if (sslConfig != null && sslConfig.isClientCertAuthenticationEnabled()) {
            bindRequest = new EXTERNALBindRequest();
        } else {
            bindRequest = new SimpleBindRequest();
        }
        
        LDAPConnectionOptions opts = new LDAPConnectionOptions();
        
        int connectTimeout = settings.getAsInt(ConfigConstants.LDAP_CONNECT_TIMEOUT, opts.getConnectTimeoutMillis()); // 0 means wait infinitely
        long responseTimeout = settings.getAsLong(ConfigConstants.LDAP_RESPONSE_TIMEOUT, opts.getResponseTimeoutMillis()); // 0 means wait infinitely
        
        opts.setConnectTimeoutMillis(connectTimeout);
        opts.setResponseTimeoutMillis(responseTimeout);
        opts.setFollowReferrals(true);
        
        
        if(this.settings.hasValue(ConfigConstants.LDAP_POOL_ENABLED)) {
            //log deprecation
        }
        
        final int poolMinSize = this.settings.getAsInt(ConfigConstants.LDAP_POOL_MIN_SIZE, 3);
        final int poolMaxSize = this.settings.getAsInt(ConfigConstants.LDAP_POOL_MAX_SIZE, 10);

        pool = new LDAPConnectionPool(createServerSet(ldapStrings, opts), bindRequest, poolMinSize, poolMaxSize);
        pool.setCreateIfNecessary(!"blocking".equals(this.settings.get(ConfigConstants.LDAP_POOL_TYPE)));
        
        //pool.setHealthCheck(healthCheck);
        //System.out.println(pool.getHealthCheckIntervalMillis()); 60 sec
        //System.out.println(pool.getMinimumAvailableConnectionGoal()); 0
        
        
        userSearcher = new LDAPUserSearcher(this, settings);
    }
    
    private ServerSet createServerSet(final Collection<String> ldapStrings, LDAPConnectionOptions opts) {
        final List<String> ldapHosts = new ArrayList<>();
        final List<Integer> ldapPorts = new ArrayList<>();
        
        if(ldapStrings == null || ldapStrings.isEmpty()) {
            ldapHosts.add("localhost");
            ldapPorts.add(this.sslConfig != null?636:389);
        } else {
            for(String ldapString:ldapStrings) {
                
                if(ldapString == null || (ldapString = ldapString.trim()).isEmpty()) {
                    continue;
                }
                
                int port = this.sslConfig != null ? 636:389;
                
                if(ldapString.startsWith("ldap://")) {
                    ldapString = ldapString.replace("ldap://", "");
                    //log err
                }
                
                if(ldapString.startsWith("ldaps://")) {
                    ldapString = ldapString.replace("ldaps://", "");
                    port = 636;
                }
                
                final String[] split = ldapString.split(":");

                if (split.length > 1) {
                    port = Integer.parseInt(split[1]);
                }
                
                ldapHosts.add(split[0]);
                ldapPorts.add(port);
            }
        }

        if(sslConfig != null && !sslConfig.isStartTlsEnabled()) {
            final SSLSocketFactory sf = sslConfig.getRestrictedSSLSocketFactory();
            return new RoundRobinServerSet(ldapHosts.toArray(new String[0]), Ints.toArray(ldapPorts), sf, opts);
        }
        
        if(sslConfig != null && sslConfig.isStartTlsEnabled()) {
            final SSLSocketFactory sf = sslConfig.getRestrictedSSLSocketFactory();
            return new RoundRobinServerSet(ldapHosts.toArray(new String[0]), Ints.toArray(ldapPorts), null, opts, null, new StartTLSPostConnectProcessor(sf));
        }
        
        return new RoundRobinServerSet(ldapHosts.toArray(new String[0]), Ints.toArray(ldapPorts), opts);
    }
    
    public LDAPConnection getConnection() throws LDAPException {
        return pool.getConnection();
    }
    
    public void checkDnPassword(String dn, String password) throws LDAPException {
        pool.bindAndRevertAuthentication(new SimpleBindRequest(dn, password));
    }
    
    public void checkDnPassword(String dn, byte[] password) throws LDAPException {
        pool.bindAndRevertAuthentication(new SimpleBindRequest(dn, password));
    }
    
    public List<SearchResultEntry> search(LDAPConnection con, final String baseDN, final SearchScope scope,
            final ParametrizedFilter filter) throws LDAPException {
            SearchRequest sr = new SearchRequest(baseDN, scope, filter.toString(), SearchRequest.ALL_OPERATIONAL_ATTRIBUTES, SearchRequest.ALL_USER_ATTRIBUTES);
            sr.setDerefPolicy(DereferencePolicy.ALWAYS);
            SearchResult searchResult = con.search(sr);
            return searchResult.getSearchEntries();
    }
    
    public SearchResultEntry lookup(LDAPConnection con, final String dn) throws LDAPException {
        return con.getEntry(dn, SearchRequest.ALL_OPERATIONAL_ATTRIBUTES, SearchRequest.ALL_USER_ATTRIBUTES);
    }
    
    public SearchResultEntry exists(LDAPConnection con, String name) throws LDAPException {
        return userSearcher.exists(con, name);
    }

    @Override
    public void close() throws IOException {
        if(pool != null) {
            pool.close();
        }
    }
}
