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
 * Holds the OSGi services used by the Authsignal connector.
 */
public class AuthsignalConnectorDataHolder {

    private static RealmService realmService;
    private static IdentityGovernanceService identityGovernanceService;

    private AuthsignalConnectorDataHolder() {

    }

    /**
     * Get the RealmService.
     *
     * @return RealmService.
     */
    public static RealmService getRealmService() {

        return realmService;
    }

    /**
     * Set the RealmService.
     *
     * @param realmService RealmService.
     */
    public static void setRealmService(RealmService realmService) {

        AuthsignalConnectorDataHolder.realmService = realmService;
    }

    /**
     * Get the IdentityGovernanceService.
     *
     * @return IdentityGovernanceService.
     */
    public static IdentityGovernanceService getIdentityGovernanceService() {

        return identityGovernanceService;
    }

    /**
     * Set the IdentityGovernanceService.
     *
     * @param identityGovernanceService IdentityGovernanceService.
     */
    public static void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        AuthsignalConnectorDataHolder.identityGovernanceService = identityGovernanceService;
    }
}
