/*
 * Copyright 2016-2019 by floragunn GmbH - All rights reserved
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

package com.floragunn.dlic;

import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;

import com.floragunn.searchguard.FipsManager;

public class AbstractNonClusterTest {
    
static {
        
    if(System.getSecurityManager() == null) {
    
        //we need a security in case we test with FIPS
        Policy.setPolicy(new Policy() {

            @Override
            public boolean implies(ProtectionDomain domain, Permission permission) {
                if(permission.getClass().getName().equals("org.bouncycastle.crypto.CryptoServicesPermission")) {
                    if(permission.getActions().equals("[unapprovedModeEnabled]")) {
                        System.out.println(permission);
                        return false;
                    }
                }
                return true;
            }
            
        });

        System.setSecurityManager(new SecurityManager());
        
        FipsManager.initialize(utFips());
        
    }
}
    
    protected static final boolean utFips() {
        return true;
    }

}
