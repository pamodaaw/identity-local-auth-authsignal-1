/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.authsignal.internal;

import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Holds the OSGi services used by the Authsignal authenticator.
 */
public class AuthsignalAuthenticatorDataHolder {

    private static RealmService realmService;
    private static IdentityGovernanceService identityGovernanceService;

    private AuthsignalAuthenticatorDataHolder() {

    }

    /**
     * Get the RealmService.
     *
     * @return RealmService.
     */
    public static RealmService getRealmService() {

        if (realmService == null) {
            throw new IllegalStateException(
                    "RealmService was not set during the Authsignal authenticator service component startup");
        }
        return realmService;
    }

    /**
     * Set the RealmService.
     *
     * @param realmService RealmService.
     */
    public static void setRealmService(RealmService realmService) {

        AuthsignalAuthenticatorDataHolder.realmService = realmService;
    }

    /**
     * Get the IdentityGovernanceService.
     *
     * @return IdentityGovernanceService.
     */
    public static IdentityGovernanceService getIdentityGovernanceService() {

        if (identityGovernanceService == null) {
            throw new IllegalStateException(
                    "IdentityGovernanceService was not set during the Authsignal authenticator service component "
                            + "startup");
        }
        return identityGovernanceService;
    }

    /**
     * Set the IdentityGovernanceService.
     *
     * @param identityGovernanceService IdentityGovernanceService.
     */
    public static void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        AuthsignalAuthenticatorDataHolder.identityGovernanceService = identityGovernanceService;
    }
}
