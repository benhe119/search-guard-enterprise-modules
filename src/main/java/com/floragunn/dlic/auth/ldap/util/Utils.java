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

package com.floragunn.dlic.auth.ldap.util;

import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;
import org.ldaptive.Connection;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapUtils;
import org.ldaptive.ssl.CredentialConfig;
import org.ldaptive.ssl.DefaultTrustManager;
import org.ldaptive.ssl.HostnameVerifyingTrustManager;
import org.ldaptive.ssl.KeyStoreSSLContextInitializer;
import org.ldaptive.ssl.X509SSLContextInitializer;

public final class Utils {
    
    private static final Logger log = LogManager.getLogger(Utils.class);

    private Utils() {

    }

    public static void unbindAndCloseSilently(final Connection connection) {
        if (connection == null) {
            return;
        }

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Object>() {
                @Override
                public Object run() throws Exception {
                    connection.close(); //this never throws an exception
                    //see org.ldaptive.DefaultConnectionFactory.DefaultConnection#close()
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            // ignore
        }
    }
    
    public static List<Map.Entry<String, Settings>> getOrderedBaseSettings(Settings settings) {
        return getOrderedBaseSettings(settings.getAsGroups());
    }
    
    public static List<Map.Entry<String, Settings>> getOrderedBaseSettings(Map<String, Settings> settingsMap) {
        return getOrderedBaseSettings(settingsMap.entrySet());
    }

    public static List<Map.Entry<String, Settings>> getOrderedBaseSettings(Set<Map.Entry<String, Settings>> set) {
        List<Map.Entry<String, Settings>> result = new ArrayList<>(set);

        sortBaseSettings(result);

        return Collections.unmodifiableList(result);
    }

    private static void sortBaseSettings(List<Map.Entry<String, Settings>> list) {
        list.sort(new Comparator<Map.Entry<String, Settings>>() {

            @Override
            public int compare(Map.Entry<String, Settings> o1, Map.Entry<String, Settings> o2) {
                int attributeOrder = Integer.compare(o1.getValue().getAsInt("order", Integer.MAX_VALUE),
                        o2.getValue().getAsInt("order", Integer.MAX_VALUE));

                if (attributeOrder != 0) {
                    return attributeOrder;
                }

                return o1.getKey().compareTo(o2.getKey());
            }
        });
    }
    
    public static String getSingleStringValue(LdapAttribute attribute) {
        if(attribute == null) {
            return null;
        }
        
        if(attribute.size() > 1) {
            if(log.isDebugEnabled()) {
                log.debug("Multiple values found for {} ({})", attribute.getName(), attribute);
            }
        }
        
        return attribute.getStringValue();
    }
    
    public static CredentialConfig createX509CredentialConfig(
            final X509Certificate[] trustCertificates,
            final X509Certificate authenticationCertificate,
            final PrivateKey authenticationKey)
          {
            return
              () -> {
                final X509SSLContextInitializer sslInit = new X509SSLContextInitializer(){

                    @Override
                    public TrustManager[] getTrustManagers() throws GeneralSecurityException {
                        final TrustManager[] tm = createTrustManagers();
                        final TrustManager[] hostnameTrustManager = hostnameVerifierConfig != null ?xxx
                          new TrustManager[] {
                            new HostnameVerifyingTrustManager(
                              hostnameVerifierConfig.getCertificateHostnameVerifier(),
                              hostnameVerifierConfig.getHostnames()),
                          } : null;

                        if (tm == null) {
                            throw new RuntimeException("tm null");
                        } else {
                            
                            if(trustManagers != null) throw new RuntimeException("trustManagers");
                            //if(hostnameTrustManager != null) throw new RuntimeException("hostnameTrustManager");
                            
                            return tm;
                        }
                    }
                    
                };
                if (trustCertificates != null) {
                  sslInit.setTrustCertificates(trustCertificates);
                }
                if (authenticationCertificate != null) {
                  sslInit.setAuthenticationCertificate(authenticationCertificate);
                }
                if (authenticationKey != null) {
                  sslInit.setAuthenticationKey(authenticationKey);
                }
                return sslInit;
              };
          }
    
    
    public static CredentialConfig createKeyStoreCredentialConfig(
            final KeyStore trustStore,
            final String[] trustStoreAliases,
            final KeyStore keyStore,
            final String keyStorePassword,
            final String[] keyStoreAliases)
          {
            return
              () -> {
                final KeyStoreSSLContextInitializer sslInit = new KeyStoreSSLContextInitializer() {

                    @Override
                    public TrustManager[] getTrustManagers() throws GeneralSecurityException {
                        final TrustManager[] tm = createTrustManagers();
                        final TrustManager[] hostnameTrustManager = hostnameVerifierConfig != null ?xxx
                          new TrustManager[] {
                            new HostnameVerifyingTrustManager(
                              hostnameVerifierConfig.getCertificateHostnameVerifier(),
                              hostnameVerifierConfig.getHostnames()),
                          } : null;

                        if (tm == null) {
                            throw new RuntimeException("tm null");
                        } else {
                            
                            if(trustManagers != null) throw new RuntimeException("trustManagers");
                            //if(hostnameTrustManager != null) throw new RuntimeException("hostnameTrustManager");
                            
                            return tm;
                        }
                    }

                    
                    
                };
                if (trustStore != null) {
                  sslInit.setTrustKeystore(trustStore);
                  sslInit.setTrustAliases(trustStoreAliases);
                }
                if (keyStore != null) {
                  sslInit.setAuthenticationKeystore(keyStore);
                  sslInit.setAuthenticationPassword(keyStorePassword != null ? keyStorePassword.toCharArray() : null);
                  sslInit.setAuthenticationAliases(keyStoreAliases);
                }
                return sslInit;
              };
          }

}
