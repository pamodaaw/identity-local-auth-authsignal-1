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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.local.auth.authsignal.internal.AuthsignalAuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.HashMap;
import java.util.Map;

/**
 * Reads and updates local users for the authenticator, the flow executor and the listeners.
 */
public final class AuthsignalUserStoreUtil {

    private static final Log LOG = LogFactory.getLog(AuthsignalUserStoreUtil.class);

    private AuthsignalUserStoreUtil() {

    }

    /**
     * Get the user realm of a tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return User realm of the tenant.
     * @throws UserStoreException If the realm is not available.
     */
    public static UserRealm getUserRealm(String tenantDomain) throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm = AuthsignalAuthenticatorDataHolder.getRealmService().getTenantUserRealm(tenantId);
        if (userRealm == null) {
            throw new UserStoreException("User realm is not available for the tenant: " + tenantDomain);
        }
        return userRealm;
    }

    /**
     * Update claims of a user.
     *
     * @param tenantDomain            Tenant domain of the user.
     * @param domainQualifiedUsername Username with the user store domain.
     * @param claims                  Claims to update. User operation listeners add claims of their own to the map,
     *                                so it must be mutable.
     * @throws UserStoreException If the claims cannot be updated.
     */
    public static void setUserClaims(String tenantDomain, String domainQualifiedUsername, Map<String, String> claims)
            throws UserStoreException {

        getUserRealm(tenantDomain).getUserStoreManager().setUserClaimValues(domainQualifiedUsername, claims, null);
    }

    /**
     * Add whether the user has a passkey on Authsignal to the claims, if a passkey enrolled claim is configured for
     * the tenant.
     *
     * @param claims          Claims to add to.
     * @param config          Tenant configuration.
     * @param passkeyEnrolled Whether the user has a passkey on Authsignal.
     */
    public static void putPasskeyEnrolledClaim(Map<String, String> claims, AuthsignalConfig config,
                                               boolean passkeyEnrolled) {

        String claimUri = config.getPasskeyEnrolledClaim();
        if (claimUri != null) {
            claims.put(claimUri, String.valueOf(passkeyEnrolled));
        }
    }

    /**
     * Save whether the user has a passkey on Authsignal in the passkey enrolled claim configured for the tenant, if
     * any. The user is already verified when this is called, so failures are logged and never thrown.
     *
     * @param config                  Tenant configuration.
     * @param tenantDomain            Tenant domain of the user.
     * @param domainQualifiedUsername Username with the user store domain.
     * @param passkeyEnrolled         Whether the user has a passkey on Authsignal.
     */
    public static void savePasskeyEnrolledClaim(AuthsignalConfig config, String tenantDomain,
                                                String domainQualifiedUsername, boolean passkeyEnrolled) {

        Map<String, String> claims = new HashMap<>();
        putPasskeyEnrolledClaim(claims, config, passkeyEnrolled);
        if (claims.isEmpty() || StringUtils.isBlank(domainQualifiedUsername)) {
            return;
        }
        try {
            setUserClaims(tenantDomain, domainQualifiedUsername, claims);
        } catch (UserStoreException | RuntimeException e) {
            LOG.error("Failed to update the Authsignal passkey enrolled claim of the user in the tenant: "
                    + tenantDomain + ".", e);
        }
    }
}
