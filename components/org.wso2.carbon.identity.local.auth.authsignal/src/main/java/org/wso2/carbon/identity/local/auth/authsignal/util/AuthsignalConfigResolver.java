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
package org.wso2.carbon.identity.local.auth.authsignal.util;

import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.internal.AuthsignalAuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;

import java.util.HashMap;
import java.util.Map;

/**
 * Builds the Authsignal configuration of a tenant from its governance connector properties. Shared by the
 * authenticator and the flow executor.
 */
public final class AuthsignalConfigResolver {

    private AuthsignalConfigResolver() {

    }

    /**
     * Build the configuration from the governance connector properties of the tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return Tenant configuration.
     * @throws IdentityGovernanceException If the tenant configuration cannot be read.
     */
    public static AuthsignalConfig resolve(String tenantDomain)
            throws IdentityGovernanceException {

        Map<String, String> tenantProperties = new HashMap<>();
        Property[] properties = AuthsignalAuthenticatorDataHolder.getIdentityGovernanceService()
                .getConfiguration(AuthsignalConnectorConfig.PROPERTY_NAMES, tenantDomain);
        if (properties != null) {
            for (Property property : properties) {
                if (property != null && property.getName() != null) {
                    tenantProperties.put(property.getName(), property.getValue());
                }
            }
        }
        return new AuthsignalConfig(tenantProperties);
    }
}
