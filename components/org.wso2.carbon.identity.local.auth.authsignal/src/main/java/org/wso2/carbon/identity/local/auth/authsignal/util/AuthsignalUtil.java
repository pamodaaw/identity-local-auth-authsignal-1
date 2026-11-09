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
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalConnectionException;
import org.wso2.carbon.identity.local.auth.authsignal.internal.AuthsignalConnectorDataHolder;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalResponse;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.HashMap;
import java.util.Map;

/**
 * Utilities shared by the authenticator, the flow executor and the flow listener, for reading the tenant
 * configuration and reading and updating local users.
 */
public final class AuthsignalUtil {

    private static final Log LOG = LogFactory.getLog(AuthsignalUtil.class);

    private AuthsignalUtil() {

    }

    /**
     * Get the Authsignal configuration of a tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return Tenant configuration.
     * @throws IdentityGovernanceException If the tenant configuration cannot be read.
     */
    public static AuthsignalConfig getConfig(String tenantDomain) throws IdentityGovernanceException {

        Map<String, String> tenantProperties = new HashMap<>();
        Property[] properties = AuthsignalConnectorDataHolder.getIdentityGovernanceService()
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

    /**
     * Get the user realm of a tenant.
     *
     * @param tenantDomain Tenant domain.
     * @return User realm of the tenant.
     * @throws UserStoreException If the realm is not available.
     */
    public static UserRealm getUserRealm(String tenantDomain) throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm = AuthsignalConnectorDataHolder.getRealmService().getTenantUserRealm(tenantId);
        if (userRealm == null) {
            throw new UserStoreException("User realm is not available for the tenant: " + tenantDomain);
        }
        return userRealm;
    }

    /**
     * Get a claim value of a user.
     *
     * @param tenantDomain            Tenant domain of the user.
     * @param domainQualifiedUsername Username with the user store domain.
     * @param claimUri                Claim URI.
     * @return Claim value, or null if not set.
     * @throws UserStoreException If the claim cannot be read.
     */
    public static String getUserClaim(String tenantDomain, String domainQualifiedUsername, String claimUri)
            throws UserStoreException {

        return getUserRealm(tenantDomain).getUserStoreManager().getUserClaimValue(domainQualifiedUsername, claimUri,
                null);
    }

    /**
     * Update claims of a user.
     *
     * @param tenantDomain            Tenant domain of the user.
     * @param domainQualifiedUsername Username with the user store domain.
     * @param claims                  Claims to update. Must be a mutable map.
     * @throws UserStoreException If the claims cannot be updated.
     */
    public static void setUserClaims(String tenantDomain, String domainQualifiedUsername, Map<String, String> claims)
            throws UserStoreException {

        getUserRealm(tenantDomain).getUserStoreManager().setUserClaimValues(domainQualifiedUsername, claims, null);
    }

    /**
     * Add the passkey enrolled claim to the claims, if the tenant has one configured.
     *
     * @param claims          Claims to add to.
     * @param config          Tenant configuration.
     * @param passkeyEnrolled Whether the user has a passkey on Authsignal.
     */
    public static void updatePasskeyEnrolledClaim(Map<String, String> claims, AuthsignalConfig config,
                                                  boolean passkeyEnrolled) {

        String claimUri = config.getPasskeyEnrolledClaim();
        if (claimUri != null) {
            claims.put(claimUri, String.valueOf(passkeyEnrolled));
        }
    }

    /**
     * Link a user to the Authsignal user of their registration and get the claims to save on the user once linked.
     * Calls that get no response are retried by the external API client. Other transient errors are not retried
     * here, so the caller must leave the link for a later sign-in.
     *
     * @param client      Authsignal client of the tenant.
     * @param config      Tenant configuration.
     * @param userId      WSO2 user ID of the user, which becomes the Authsignal user ID.
     * @param challengeId Challenge ID of the registration flow.
     * @param email       Email address of the user, if any.
     * @param mobile      Mobile number of the user, if any.
     * @return Mutable map of the claims to save on the user.
     * @throws AuthsignalConnectionException If the link failed. It is transient if Authsignal could not be reached, so
     *                                       the link must be retried later.
     */
    public static Map<String, String> syncUserIdToAuthsignal(AuthsignalClient client, AuthsignalConfig config,
                                                             String userId, String challengeId, String email,
                                                             String mobile) throws AuthsignalConnectionException {

        AuthsignalResponse response = client.identifyUser(userId, challengeId);
        return resolveUserClaimsToBeUpdated(config, response, email, mobile);
    }

    /**
     * Get the claims of a user just linked to the Authsignal user of their registration. The email / phone verified
     * claims are set only if the user verified, with email OTP or magic link / SMS or WhatsApp, the same email address
     * / mobile number the user has. The passkey enrolled claim is set by whether the user verified a passkey. Values
     * are never copied from Authsignal.
     */
    private static Map<String, String> resolveUserClaimsToBeUpdated(AuthsignalConfig config,
                                                                    AuthsignalResponse response, String email,
                                                                    String mobile) {

        Map<String, String> claims = new HashMap<>();
        if (email != null && email.equalsIgnoreCase(response.getVerifiedEmail())) {
            claims.put(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, Boolean.TRUE.toString());
        }
        if (mobile != null && mobile.equals(response.getVerifiedPhoneNumber())) {
            claims.put(AuthsignalConstants.MOBILE_VERIFIED_CLAIM, Boolean.TRUE.toString());
        }
        updatePasskeyEnrolledClaim(claims, config, response.hasVerifiedPasskey());
        return claims;
    }

    /**
     * Save whether the user has a passkey in the passkey enrolled claim, if the tenant has one configured. Errors are
     * logged and not thrown.
     *
     * @param config                  Tenant configuration.
     * @param tenantDomain            Tenant domain of the user.
     * @param domainQualifiedUsername Username with the user store domain.
     * @param passkeyEnrolled         Whether the user has a passkey on Authsignal.
     */
    public static void savePasskeyEnrolledClaim(AuthsignalConfig config, String tenantDomain,
                                                String domainQualifiedUsername, boolean passkeyEnrolled) {

        Map<String, String> claims = new HashMap<>();
        updatePasskeyEnrolledClaim(claims, config, passkeyEnrolled);
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
