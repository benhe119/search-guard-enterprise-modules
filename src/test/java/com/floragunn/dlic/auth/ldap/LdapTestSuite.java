package com.floragunn.dlic.auth.ldap;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses({
        LdapBackendTest.class,
        LdapBackendTestClientCert.class,
        LdapAuthorizationTestNonLdapRoles.class
})
public class LdapTestSuite {

}
