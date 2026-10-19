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

package org.wso2.carbon.identity.local.auth.authsignal.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalConfigResolver;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUserIdResolver;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Keeps Authsignal's users in step with WSO2's users.
 * <p>
 * <b>User deletion.</b> When a user is deleted in WSO2, the user and their authenticators are deleted on Authsignal, so
 * that a new user given the same Authsignal user ID does not inherit them. Enabled per tenant through
 * {@link org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig#DELETE_USERS}. The
 * Authsignal user ID is resolved before the deletion, while the user still exists, and the user is deleted on
 * Authsignal only after the deletion succeeds in WSO2.
 * <p>
 * <b>Contact detail sync.</b> Updates a user's email address and mobile number on Authsignal when they change in WSO2,
 * so that Authsignal's
 * email OTP and SMS authenticators keep reaching the user. Enabled per tenant through
 * {@link org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig#SYNC_CONTACT_DETAILS}.
 * <p>
 * Only values WSO2 has verified are synced, using Authsignal's Update User API with the values marked as verified
 * ({@code emailVerified} / {@code phoneNumberVerified}). Authsignal only moves the user's email and SMS authenticators
 * to the new values when they are marked as verified, and does so without sending an OTP. A value is verified when
 * WSO2's email / phone verified claim of the user is true after the update. Unverified values and removals are not
 * synced; the user can change them through Authsignal's email and phone update flows instead.
 * <p>
 * Only the username based methods are overridden. For user stores that work with user IDs, the framework's
 * username resolver listener invokes them, so overriding the user ID based methods too would sync twice.
 * <p>
 * When verification on update is enabled, the new value is held in a pending claim until the user verifies it, and
 * the real claim (and so the sync) only changes after verification.
 * <p>
 * Calls to Authsignal never fail the user operation: the change is already stored in WSO2 when the post methods run.
 */
public class AuthsignalUserOperationEventListener extends AbstractIdentityUserOperationEventListener {

    private static final Log LOG = LogFactory.getLog(AuthsignalUserOperationEventListener.class);

    // Runs after the identity governance listener (95), which moves claims pending verification out of the update.
    private static final int DEFAULT_ORDER_ID = 120;

    /*
     * The post methods of single claim updates and of claim deletions do not receive the claims, so the pre methods
     * keep the changes of the current operation here. A null value means the claim is removed.
     */
    private static final ThreadLocal<Map<String, String>> PENDING_CHANGES = new ThreadLocal<>();

    // Authsignal user to delete once the user deletion of the current operation succeeds in WSO2.
    private static final ThreadLocal<PendingDeletion> PENDING_DELETION = new ThreadLocal<>();

    // Set while the connector itself writes contact details that Authsignal already holds.
    private static final ThreadLocal<Boolean> SYNC_DISABLED = new ThreadLocal<>();

    /**
     * Skip the sync for the claim updates made on the current thread until {@link #enableSync()} is called.
     */
    static void disableSync() {

        SYNC_DISABLED.set(Boolean.TRUE);
    }

    static void enableSync() {

        SYNC_DISABLED.remove();
    }

    @Override
    public int getExecutionOrderId() {

        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return DEFAULT_ORDER_ID;
    }

    @Override
    public boolean doPostSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                            UserStoreManager userStoreManager) throws UserStoreException {

        if (claims == null) {
            return true;
        }
        Map<String, String> changes = new HashMap<>();
        for (String claimUri : new String[]{AuthsignalConstants.EMAIL_CLAIM, AuthsignalConstants.MOBILE_CLAIM}) {
            if (claims.containsKey(claimUri)) {
                changes.put(claimUri, claims.get(claimUri));
            }
        }
        syncContactDetails(userName, userStoreManager, changes);
        return true;
    }

    @Override
    public boolean doPreSetUserClaimValue(String userName, String claimURI, String claimValue, String profileName,
                                          UserStoreManager userStoreManager) throws UserStoreException {

        Map<String, String> changes = new HashMap<>();
        if (isContactClaim(claimURI)) {
            changes.put(claimURI, claimValue);
        }
        PENDING_CHANGES.set(changes);
        return true;
    }

    @Override
    public boolean doPostSetUserClaimValue(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        syncPendingChanges(userName, userStoreManager);
        return true;
    }

    @Override
    public boolean doPreDeleteUserClaimValue(String userName, String claimURI, String profileName,
                                             UserStoreManager userStoreManager) throws UserStoreException {

        Map<String, String> changes = new HashMap<>();
        if (isContactClaim(claimURI)) {
            changes.put(claimURI, null);
        }
        PENDING_CHANGES.set(changes);
        return true;
    }

    @Override
    public boolean doPostDeleteUserClaimValue(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        syncPendingChanges(userName, userStoreManager);
        return true;
    }

    @Override
    public boolean doPreDeleteUserClaimValues(String userName, String[] claims, String profileName,
                                              UserStoreManager userStoreManager) throws UserStoreException {

        Map<String, String> changes = new HashMap<>();
        if (claims != null) {
            for (String claimUri : claims) {
                if (isContactClaim(claimUri)) {
                    changes.put(claimUri, null);
                }
            }
        }
        PENDING_CHANGES.set(changes);
        return true;
    }

    @Override
    public boolean doPostDeleteUserClaimValues(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        syncPendingChanges(userName, userStoreManager);
        return true;
    }

    @Override
    public boolean doPreDeleteUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {

        // Always replace the state, so that a deletion that failed after this ran cannot leak into the next one.
        PENDING_DELETION.remove();
        PendingDeletion pendingDeletion = resolvePendingDeletion(userName, userStoreManager);
        if (pendingDeletion != null) {
            PENDING_DELETION.set(pendingDeletion);
        }
        return true;
    }

    @Override
    public boolean doPostDeleteUser(String userName, UserStoreManager userStoreManager) throws UserStoreException {

        try {
            PendingDeletion pendingDeletion = PENDING_DELETION.get();
            if (pendingDeletion != null && pendingDeletion.userName.equals(userName)) {
                deleteAuthsignalUser(pendingDeletion);
            }
        } finally {
            PENDING_DELETION.remove();
        }
        return true;
    }

    /**
     * Resolve the Authsignal user to delete along with a WSO2 user. Runs before the deletion, as resolving the
     * Authsignal user ID may need to read the user. Failures are logged and never propagated.
     *
     * @return The Authsignal user to delete, or null if nothing is to be deleted on Authsignal.
     */
    private PendingDeletion resolvePendingDeletion(String userName, UserStoreManager userStoreManager) {

        String tenantDomain = null;
        try {
            tenantDomain = getTenantDomain(userStoreManager);
            AuthsignalConfig config = resolveConfig(tenantDomain);
            if (!config.isDeleteUsers() || StringUtils.isBlank(config.getSecretKey())) {
                return null;
            }
            String userStoreDomain = userStoreManager.getRealmConfiguration()
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
            String authsignalUserId = resolveAuthsignalUserId(tenantDomain, userStoreDomain,
                    UserCoreUtil.removeDomainFromName(userName), config);
            if (StringUtils.isBlank(authsignalUserId)) {
                return null;
            }
            return new PendingDeletion(userName, tenantDomain, authsignalUserId, config);
        } catch (IdentityGovernanceException | org.wso2.carbon.user.api.UserStoreException | RuntimeException e) {
            logDeletionFailure(tenantDomain, e);
            return null;
        }
    }

    private void deleteAuthsignalUser(PendingDeletion pendingDeletion) {

        try {
            createClient(pendingDeletion.config).deleteUser(pendingDeletion.authsignalUserId);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Deleted a user on Authsignal in the tenant: " + pendingDeletion.tenantDomain);
            }
        } catch (AuthsignalClientException e) {
            if (e.getStatusCode() == 404) {
                // The user never enrolled on Authsignal, so there is nothing to delete.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("The user does not exist on Authsignal. Skipping the user deletion in the tenant: "
                            + pendingDeletion.tenantDomain);
                }
                return;
            }
            logDeletionFailure(pendingDeletion.tenantDomain, e);
        } catch (RuntimeException e) {
            logDeletionFailure(pendingDeletion.tenantDomain, e);
        }
    }

    private static void logDeletionFailure(String tenantDomain, Exception e) {

        LOG.warn("Failed to delete a user on Authsignal in the tenant: " + tenantDomain
                + ". The user's authenticators remain on Authsignal and must be deleted there.");
        if (LOG.isDebugEnabled()) {
            LOG.debug("Error while deleting a user on Authsignal.", e);
        }
    }

    private void syncPendingChanges(String userName, UserStoreManager userStoreManager) {

        try {
            Map<String, String> changes = PENDING_CHANGES.get();
            if (changes != null) {
                syncContactDetails(userName, userStoreManager, changes);
            }
        } finally {
            PENDING_CHANGES.remove();
        }
    }

    /**
     * Update the changed, verified contact claims of a user on Authsignal as verified. Failures are logged and never
     * propagated.
     *
     * @param userName         Username, optionally with the user store domain.
     * @param userStoreManager User store manager of the user.
     * @param changes          Changed contact claims keyed by claim URI. A blank or null value means the claim is
     *                         removed, which is not synced.
     */
    void syncContactDetails(String userName, UserStoreManager userStoreManager, Map<String, String> changes) {

        if (changes.isEmpty() || Boolean.TRUE.equals(SYNC_DISABLED.get())) {
            return;
        }
        String tenantDomain = null;
        try {
            tenantDomain = getTenantDomain(userStoreManager);
            AuthsignalConfig config = resolveConfig(tenantDomain);
            if (!config.isSyncContactDetails() || StringUtils.isBlank(config.getSecretKey())) {
                return;
            }

            Map<String, String> verifiedChanges = getVerifiedChanges(userName, userStoreManager, changes);
            if (verifiedChanges.isEmpty()) {
                return;
            }

            String userStoreDomain = userStoreManager.getRealmConfiguration()
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
            String authsignalUserId = resolveAuthsignalUserId(tenantDomain, userStoreDomain,
                    UserCoreUtil.removeDomainFromName(userName), config);
            if (StringUtils.isBlank(authsignalUserId)) {
                return;
            }
            createClient(config).updateVerifiedContactDetails(authsignalUserId,
                    verifiedChanges.get(AuthsignalConstants.EMAIL_CLAIM),
                    verifiedChanges.get(AuthsignalConstants.MOBILE_CLAIM));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Updated " + verifiedChanges.keySet() + " of a user on Authsignal as verified in the "
                        + "tenant: " + tenantDomain);
            }
        } catch (AuthsignalClientException e) {
            if (e.getStatusCode() == 404) {
                // The user never enrolled on Authsignal, so there is nothing to keep in sync.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("The user does not exist on Authsignal. Skipping the contact detail sync in the "
                            + "tenant: " + tenantDomain);
                }
                return;
            }
            logSyncFailure(tenantDomain, e);
        } catch (IdentityGovernanceException | org.wso2.carbon.user.api.UserStoreException | RuntimeException e) {
            logSyncFailure(tenantDomain, e);
        }
    }

    /**
     * Keep the new email address and mobile number that the user has verified in WSO2. The verified claims are
     * identity claims, which are removed from the claims of the update before this listener runs, so they are read
     * back from the user. A mobile number that is not in E.164 format is skipped, as Authsignal rejects it.
     *
     * @return Verified new values keyed by claim URI.
     */
    private static Map<String, String> getVerifiedChanges(String userName, UserStoreManager userStoreManager,
                                                          Map<String, String> changes) {

        Map<String, String> newValues = new LinkedHashMap<>();
        String email = StringUtils.trimToNull(changes.get(AuthsignalConstants.EMAIL_CLAIM));
        if (email != null) {
            newValues.put(AuthsignalConstants.EMAIL_CLAIM, email);
        }
        String mobile = StringUtils.trimToNull(changes.get(AuthsignalConstants.MOBILE_CLAIM));
        if (mobile != null && mobile.startsWith("+")) {
            newValues.put(AuthsignalConstants.MOBILE_CLAIM, mobile);
        } else if (mobile != null && LOG.isDebugEnabled()) {
            LOG.debug("The mobile number is not in E.164 format. Skipping the sync of the mobile number.");
        }
        if (newValues.isEmpty()) {
            return newValues;
        }

        Map<String, String> verifiedClaims;
        try {
            verifiedClaims = userStoreManager.getUserClaimValues(userName, new String[]{
                    AuthsignalConstants.EMAIL_VERIFIED_CLAIM, AuthsignalConstants.MOBILE_VERIFIED_CLAIM}, null);
        } catch (UserStoreException | RuntimeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to read the verified status of the user's contact details.", e);
            }
            return new LinkedHashMap<>();
        }
        if (verifiedClaims == null
                || !Boolean.parseBoolean(verifiedClaims.get(AuthsignalConstants.EMAIL_VERIFIED_CLAIM))) {
            newValues.remove(AuthsignalConstants.EMAIL_CLAIM);
        }
        if (verifiedClaims == null
                || !Boolean.parseBoolean(verifiedClaims.get(AuthsignalConstants.MOBILE_VERIFIED_CLAIM))) {
            newValues.remove(AuthsignalConstants.MOBILE_CLAIM);
        }
        if (newValues.isEmpty() && LOG.isDebugEnabled()) {
            LOG.debug("The changed contact details are not verified in WSO2. Skipping the sync.");
        }
        return newValues;
    }

    private static boolean isContactClaim(String claimUri) {

        return AuthsignalConstants.EMAIL_CLAIM.equals(claimUri) || AuthsignalConstants.MOBILE_CLAIM.equals(claimUri);
    }

    private static void logSyncFailure(String tenantDomain, Exception e) {

        LOG.warn("Failed to update the contact details of a user on Authsignal in the tenant: " + tenantDomain
                + ". The change is kept in the user store only.");
        if (LOG.isDebugEnabled()) {
            LOG.debug("Error while updating the contact details of a user on Authsignal.", e);
        }
    }

    protected String getTenantDomain(UserStoreManager userStoreManager) throws UserStoreException {

        return IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
    }

    protected AuthsignalConfig resolveConfig(String tenantDomain) throws IdentityGovernanceException {

        return AuthsignalConfigResolver.resolve(tenantDomain);
    }

    protected String resolveAuthsignalUserId(String tenantDomain, String userStoreDomain, String username,
                                             AuthsignalConfig config)
            throws org.wso2.carbon.user.api.UserStoreException {

        return AuthsignalUserIdResolver.resolveLocalUserId(tenantDomain, userStoreDomain, username, config);
    }

    protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalClientException {

        return AuthsignalClient.forConfig(config);
    }

    /**
     * Authsignal user resolved before a WSO2 user deletion.
     */
    private static final class PendingDeletion {

        private final String userName;
        private final String tenantDomain;
        private final String authsignalUserId;
        private final AuthsignalConfig config;

        private PendingDeletion(String userName, String tenantDomain, String authsignalUserId,
                                AuthsignalConfig config) {

            this.userName = userName;
            this.tenantDomain = tenantDomain;
            this.authsignalUserId = authsignalUserId;
            this.config = config;
        }
    }
}
