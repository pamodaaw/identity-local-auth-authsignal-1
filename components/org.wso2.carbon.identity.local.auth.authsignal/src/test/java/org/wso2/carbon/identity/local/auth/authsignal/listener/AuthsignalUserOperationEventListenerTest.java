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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Tests for {@link AuthsignalUserOperationEventListener}.
 */
public class AuthsignalUserOperationEventListenerTest {

    private static final String TENANT = "carbon.super";
    private static final String USER_UUID = "8f1c1c0e-3a3b-4d3a-9a51-111111111111";
    private static final String EMAIL = "new@example.com";
    private static final String MOBILE = "+94771234567";

    private AuthsignalClient client;
    private UserStoreManager userStoreManager;
    private Map<String, String> tenantProperties;
    private String resolvedUsername;
    private String resolvedUserStoreDomain;
    private TestableListener listener;

    @BeforeMethod
    public void setUp() throws Exception {

        client = mock(AuthsignalClient.class);
        userStoreManager = mock(UserStoreManager.class);
        RealmConfiguration realmConfiguration = mock(RealmConfiguration.class);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(realmConfiguration.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME))
                .thenReturn("PRIMARY");
        tenantProperties = new HashMap<>();
        tenantProperties.put(AuthsignalConnectorConfig.SECRET_KEY, "secret");
        tenantProperties.put(AuthsignalConnectorConfig.SYNC_CONTACT_DETAILS, "true");
        resolvedUsername = null;
        resolvedUserStoreDomain = null;
        listener = new TestableListener();
    }

    @Test
    public void testExecutionOrder() {

        assertEquals(listener.getExecutionOrderId(), 120);
    }

    @Test
    public void testVerifiedEmailIsUpdated() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");
        Map<String, String> claims = new HashMap<>();
        claims.put(AuthsignalConstants.EMAIL_CLAIM, EMAIL);
        claims.put("http://wso2.org/claims/givenname", "Jane");

        assertTrue(listener.doPostSetUserClaimValues("jane", claims, null, userStoreManager));

        verify(client).updateVerifiedContactDetails(USER_UUID, EMAIL, null);
        assertEquals(resolvedUsername, "jane");
        assertEquals(resolvedUserStoreDomain, "PRIMARY");
    }

    @Test
    public void testVerifiedEmailAndMobileAreUpdatedTogether() throws Exception {

        Map<String, String> verified = new HashMap<>();
        verified.put(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");
        verified.put(AuthsignalConstants.MOBILE_VERIFIED_CLAIM, "true");
        when(userStoreManager.getUserClaimValues(eq("jane"), any(String[].class), any())).thenReturn(verified);
        Map<String, String> claims = new HashMap<>();
        claims.put(AuthsignalConstants.EMAIL_CLAIM, EMAIL);
        claims.put(AuthsignalConstants.MOBILE_CLAIM, MOBILE);

        listener.doPostSetUserClaimValues("jane", claims, null, userStoreManager);

        verify(client).updateVerifiedContactDetails(USER_UUID, EMAIL, MOBILE);
    }

    @Test
    public void testUnverifiedChangeIsNotUpdated() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "false");

        listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager);

        verifyNoUpdate();
    }

    @Test
    public void testOnlyVerifiedValueIsUpdated() throws Exception {

        verifiedClaims(AuthsignalConstants.MOBILE_VERIFIED_CLAIM, "true");
        Map<String, String> claims = new HashMap<>();
        claims.put(AuthsignalConstants.EMAIL_CLAIM, EMAIL);
        claims.put(AuthsignalConstants.MOBILE_CLAIM, MOBILE);

        listener.doPostSetUserClaimValues("jane", claims, null, userStoreManager);

        verify(client).updateVerifiedContactDetails(USER_UUID, null, MOBILE);
    }

    @Test
    public void testVerifiedStatusReadFailureMakesNoCall() throws Exception {

        when(userStoreManager.getUserClaimValues(eq("jane"), any(String[].class), any()))
                .thenThrow(new UserStoreException("boom"));

        listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager);

        verifyNoUpdate();
    }

    @Test
    public void testDomainIsRemovedFromUsername() throws Exception {

        when(userStoreManager.getUserClaimValues(eq("PRIMARY/jane"), any(String[].class), any()))
                .thenReturn(Collections.singletonMap(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true"));

        listener.doPostSetUserClaimValues("PRIMARY/jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager);

        assertEquals(resolvedUsername, "jane");
        verify(client).updateVerifiedContactDetails(USER_UUID, EMAIL, null);
    }

    @Test
    public void testNonE164MobileIsSkipped() throws Exception {

        verifiedClaims(AuthsignalConstants.MOBILE_VERIFIED_CLAIM, "true");

        listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.MOBILE_CLAIM, "0771234567"), null, userStoreManager);

        verifyNoUpdate();
    }

    @Test
    public void testRemovalIsNotSynced() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");

        listener.doPreDeleteUserClaimValue("jane", AuthsignalConstants.EMAIL_CLAIM, null, userStoreManager);
        listener.doPostDeleteUserClaimValue("jane", userStoreManager);
        listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, " "), null, userStoreManager);

        verifyNoUpdate();
    }

    @Test
    public void testSingleClaimUpdateIsSynced() throws Exception {

        verifiedClaims(AuthsignalConstants.MOBILE_VERIFIED_CLAIM, "true");

        listener.doPreSetUserClaimValue("jane", AuthsignalConstants.MOBILE_CLAIM, MOBILE, null, userStoreManager);
        listener.doPostSetUserClaimValue("jane", userStoreManager);

        verify(client).updateVerifiedContactDetails(USER_UUID, null, MOBILE);
    }

    @Test
    public void testSingleOtherClaimUpdateMakesNoCall() throws Exception {

        listener.doPreSetUserClaimValue("jane", "http://wso2.org/claims/givenname", "Jane", null, userStoreManager);
        listener.doPostSetUserClaimValue("jane", userStoreManager);

        verifyNoUpdate();
    }

    @Test
    public void testDisabledSyncMakesNoCall() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");
        tenantProperties.put(AuthsignalConnectorConfig.SYNC_CONTACT_DETAILS, "false");

        listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager);

        verifyNoUpdate();
    }

    @Test
    public void testSyncIsDisabledByDefault() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");
        tenantProperties.remove(AuthsignalConnectorConfig.SYNC_CONTACT_DETAILS);

        listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager);

        verifyNoUpdate();
    }

    @Test
    public void testMissingSecretKeyMakesNoCall() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");
        tenantProperties.remove(AuthsignalConnectorConfig.SECRET_KEY);

        listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager);

        verifyNoUpdate();
    }

    @Test
    public void testSyncDisabledForConnectorWrites() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");

        AuthsignalUserOperationEventListener.disableSync();
        try {
            listener.doPostSetUserClaimValues("jane",
                    Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager);
        } finally {
            AuthsignalUserOperationEventListener.enableSync();
        }
        verifyNoUpdate();

        listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager);
        verify(client).updateVerifiedContactDetails(USER_UUID, EMAIL, null);
    }

    @Test
    public void testClientFailureDoesNotFailOperation() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");
        doThrow(new AuthsignalClientException("down", 500)).when(client)
                .updateVerifiedContactDetails(any(), any(), any());

        assertTrue(listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager));
    }

    @Test
    public void testUnknownUserDoesNotFailOperation() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");
        doThrow(new AuthsignalClientException("not found", 404)).when(client)
                .updateVerifiedContactDetails(any(), any(), any());

        assertTrue(listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager));
    }

    @Test
    public void testRuntimeFailureDoesNotFailOperation() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");
        listener.failResolve = true;

        assertTrue(listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager));
        verifyNoUpdate();
    }

    @Test
    public void testUnresolvedUserMakesNoCall() throws Exception {

        verifiedClaims(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true");
        listener.authsignalUserId = null;

        listener.doPostSetUserClaimValues("jane",
                Collections.singletonMap(AuthsignalConstants.EMAIL_CLAIM, EMAIL), null, userStoreManager);

        verifyNoUpdate();
    }

    @Test
    public void testDeletedUserIsDeletedOnAuthsignal() throws Exception {

        assertTrue(listener.doPreDeleteUser("PRIMARY/jane", userStoreManager));
        verify(client, never()).deleteUser(any());
        assertTrue(listener.doPostDeleteUser("PRIMARY/jane", userStoreManager));

        verify(client).deleteUser(USER_UUID);
        assertEquals(resolvedUsername, "jane");
        assertEquals(resolvedUserStoreDomain, "PRIMARY");
    }

    @Test
    public void testUserIdIsResolvedBeforeDeletion() throws Exception {

        listener.doPreDeleteUser("jane", userStoreManager);
        // The user no longer exists in WSO2 once deleted.
        listener.authsignalUserId = null;
        listener.doPostDeleteUser("jane", userStoreManager);

        verify(client).deleteUser(USER_UUID);
    }

    @Test
    public void testUserDeletionIsEnabledByDefault() throws Exception {

        tenantProperties.remove(AuthsignalConnectorConfig.DELETE_USERS);

        listener.doPreDeleteUser("jane", userStoreManager);
        listener.doPostDeleteUser("jane", userStoreManager);

        verify(client).deleteUser(USER_UUID);
    }

    @Test
    public void testDisabledUserDeletionMakesNoCall() throws Exception {

        tenantProperties.put(AuthsignalConnectorConfig.DELETE_USERS, "false");

        listener.doPreDeleteUser("jane", userStoreManager);
        listener.doPostDeleteUser("jane", userStoreManager);

        verify(client, never()).deleteUser(any());
    }

    @Test
    public void testUserDeletionWithoutSecretKeyMakesNoCall() throws Exception {

        tenantProperties.remove(AuthsignalConnectorConfig.SECRET_KEY);

        listener.doPreDeleteUser("jane", userStoreManager);
        listener.doPostDeleteUser("jane", userStoreManager);

        verify(client, never()).deleteUser(any());
    }

    @Test
    public void testFailedDeletionDoesNotLeakIntoNextDeletion() throws Exception {

        // The WSO2 deletion of jane fails after the pre method, so the post method never runs for her.
        listener.doPreDeleteUser("jane", userStoreManager);
        listener.authsignalUserId = "other-id";
        listener.doPreDeleteUser("john", userStoreManager);
        listener.doPostDeleteUser("john", userStoreManager);

        verify(client).deleteUser("other-id");
        verify(client, never()).deleteUser(USER_UUID);
    }

    @Test
    public void testPostDeletionOfAnotherUserMakesNoCall() throws Exception {

        listener.doPreDeleteUser("jane", userStoreManager);
        listener.doPostDeleteUser("john", userStoreManager);
        listener.doPostDeleteUser("jane", userStoreManager);

        verify(client, never()).deleteUser(any());
    }

    @Test
    public void testUnresolvedUserIsNotDeleted() throws Exception {

        listener.authsignalUserId = null;

        listener.doPreDeleteUser("jane", userStoreManager);
        listener.doPostDeleteUser("jane", userStoreManager);

        verify(client, never()).deleteUser(any());
    }

    @Test
    public void testResolveFailureDoesNotFailDeletion() throws Exception {

        listener.failResolve = true;

        assertTrue(listener.doPreDeleteUser("jane", userStoreManager));
        assertTrue(listener.doPostDeleteUser("jane", userStoreManager));
        verify(client, never()).deleteUser(any());
    }

    @Test
    public void testClientFailureDoesNotFailDeletion() throws Exception {

        doThrow(new AuthsignalClientException("down", 500)).when(client).deleteUser(any());

        listener.doPreDeleteUser("jane", userStoreManager);
        assertTrue(listener.doPostDeleteUser("jane", userStoreManager));
    }

    @Test
    public void testUnknownUserDoesNotFailDeletion() throws Exception {

        doThrow(new AuthsignalClientException("not found", 404)).when(client).deleteUser(any());

        listener.doPreDeleteUser("jane", userStoreManager);
        assertTrue(listener.doPostDeleteUser("jane", userStoreManager));
    }

    private void verifiedClaims(String claimUri, String value) throws Exception {

        when(userStoreManager.getUserClaimValues(eq("jane"), any(String[].class), any()))
                .thenReturn(Collections.singletonMap(claimUri, value));
    }

    private void verifyNoUpdate() throws Exception {

        verify(client, never()).updateVerifiedContactDetails(any(), any(), any());
    }

    private class TestableListener extends AuthsignalUserOperationEventListener {

        private String authsignalUserId = USER_UUID;
        private boolean failResolve;

        @Override
        protected String getTenantDomain(UserStoreManager userStoreManager) {

            return TENANT;
        }

        @Override
        protected AuthsignalConfig resolveConfig(String tenantDomain) {

            return new AuthsignalConfig(tenantProperties);
        }

        @Override
        protected String resolveAuthsignalUserId(String tenantDomain, String userStoreDomain, String username,
                                                 AuthsignalConfig config) {

            if (failResolve) {
                throw new IllegalStateException("realm not available");
            }
            resolvedUsername = username;
            resolvedUserStoreDomain = userStoreDomain;
            return authsignalUserId;
        }

        @Override
        protected AuthsignalClient createClient(AuthsignalConfig config) {

            return client;
        }
    }
}
