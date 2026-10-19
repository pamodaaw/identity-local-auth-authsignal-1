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

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.executor.AuthsignalExecutor;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.FlowResponse;
import org.wso2.carbon.identity.local.auth.authsignal.util.ClaimUpdateRecorder;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Tests for {@link AuthsignalFlowExecutionListener}.
 */
public class AuthsignalFlowExecutionListenerTest {

    private static final String TENANT = "carbon.super";
    private static final String USER_UUID = "8f1c1c0e-3a3b-4d3a-9a51-111111111111";
    private static final String EMAIL = "jane@example.com";
    private static final String MOBILE = "+94771234567";
    private static final String PASSKEY_CLAIM = "http://wso2.org/claims/authsignalPasskeyEnrolled";

    private AuthsignalClient client;
    private Map<String, String> tenantProperties;
    private TestableListener listener;
    private ClaimUpdateRecorder claimUpdates;
    private boolean syncDisabledWhileSaving;

    @BeforeMethod
    public void setUp() {

        client = mock(AuthsignalClient.class);
        tenantProperties = new HashMap<>();
        tenantProperties.put(AuthsignalConnectorConfig.SECRET_KEY, "secret");
        tenantProperties.put(AuthsignalConnectorConfig.PASSKEY_ENROLLED_CLAIM, PASSKEY_CLAIM);
        listener = new TestableListener();
        syncDisabledWhileSaving = false;
        claimUpdates = ClaimUpdateRecorder.start();
        // The user operation listener ignores changes made while the sync is disabled.
        claimUpdates.onUpdate(() -> syncDisabledWhileSaving =
                new AuthsignalUserOperationEventListenerProbe().isSyncDisabled());
    }

    @AfterMethod
    public void tearDown() {

        claimUpdates.close();
    }

    @Test
    public void testCompletedRegistrationIdentifiesUserAndSavesContactDetails() throws Exception {

        FlowExecutionContext context = registrationContext();
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(EMAIL, MOBILE));

        assertTrue(listener.doPostExecute(step("COMPLETE"), context));

        verify(client).identifyUser(USER_UUID, "challenge-1");
        // The primary user store domain is implicit.
        assertEquals(claimUpdates.getUsername(), "jane");
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.EMAIL_CLAIM), EMAIL);
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.EMAIL_VERIFIED_CLAIM), "true");
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.MOBILE_CLAIM), MOBILE);
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.MOBILE_VERIFIED_CLAIM), "true");
        assertEquals(claimUpdates.getClaims().get(PASSKEY_CLAIM), "false");
        assertTrue(syncDisabledWhileSaving, "Saving must not enrol the values on Authsignal again");
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID), "Identify runs once");
    }

    @Test
    public void testOnlyVerifiedValuesAreSaved() throws Exception {

        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(EMAIL, null));

        listener.doPostExecute(step("COMPLETE"), registrationContext());

        assertEquals(claimUpdates.getClaims().size(), 3);
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.EMAIL_CLAIM), EMAIL);
    }

    @Test
    public void testPasskeyEnrolledIsNotSavedWithoutConfiguredClaim() throws Exception {

        tenantProperties.remove(AuthsignalConnectorConfig.PASSKEY_ENROLLED_CLAIM);
        FlowExecutionContext context = registrationContext();
        context.setProperty(AuthsignalExecutor.CONTEXT_PROP_PASSKEY_ENROLLED, Boolean.TRUE);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(EMAIL, null));

        listener.doPostExecute(step("COMPLETE"), context);

        assertEquals(claimUpdates.getClaims().size(), 2);
        assertFalse(claimUpdates.getClaims().containsKey(PASSKEY_CLAIM));
    }

    @Test
    public void testNothingSavedWithoutVerifiedValuesOrConfiguredClaim() throws Exception {

        tenantProperties.remove(AuthsignalConnectorConfig.PASSKEY_ENROLLED_CLAIM);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(null, null));

        listener.doPostExecute(step("COMPLETE"), registrationContext());

        assertNull(claimUpdates.getClaims());
    }

    @Test
    public void testPasskeyEnrolledInFlowIsSaved() throws Exception {

        FlowExecutionContext context = registrationContext();
        context.setProperty(AuthsignalExecutor.CONTEXT_PROP_PASSKEY_ENROLLED, Boolean.TRUE);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(EMAIL, null));

        listener.doPostExecute(step("COMPLETE"), context);

        assertEquals(claimUpdates.getClaims().get(PASSKEY_CLAIM), "true");
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_PASSKEY_ENROLLED));
    }

    @Test
    public void testPasskeyOfIdentifiedUserIsSaved() throws Exception {

        FlowResponse response = identified(EMAIL, null);
        FlowResponse.Authenticator passkey = new FlowResponse.Authenticator();
        passkey.setVerificationMethod("PASSKEY");
        response.getUser().setAuthenticators(Arrays.asList(response.getUser().getAuthenticators().get(0), passkey));
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(response);

        listener.doPostExecute(step("COMPLETE"), registrationContext());

        assertEquals(claimUpdates.getClaims().get(PASSKEY_CLAIM), "true");
    }

    @Test
    public void testUsernameIdentifier() throws Exception {

        tenantProperties.put(AuthsignalConnectorConfig.USER_IDENTIFIER, "username");
        when(client.identifyUser("jane", "challenge-1")).thenReturn(identified(null, null));

        listener.doPostExecute(step("COMPLETE"), registrationContext());

        verify(client).identifyUser("jane", "challenge-1");
        assertEquals(claimUpdates.getClaims(),
                Collections.singletonMap(PASSKEY_CLAIM, "false"));
    }

    @Test
    public void testIncompleteFlowIsIgnored() throws Exception {

        FlowExecutionContext context = registrationContext();

        assertTrue(listener.doPostExecute(step("INCOMPLETE"), context));

        verify(client, never()).identifyUser(anyString(), anyString());
        assertEquals(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID), "challenge-1");
    }

    @Test
    public void testOtherFlowTypesAreIgnored() throws Exception {

        FlowExecutionContext context = registrationContext();
        context.setFlowType(AuthsignalExecutor.PASSWORD_RECOVERY);

        listener.doPostExecute(step("COMPLETE"), context);

        verify(client, never()).identifyUser(anyString(), anyString());
    }

    @Test
    public void testRegistrationWithoutAuthsignalIsIgnored() throws Exception {

        FlowExecutionContext context = registrationContext();
        context.getProperties().remove(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID);

        listener.doPostExecute(step("COMPLETE"), context);

        verify(client, never()).identifyUser(anyString(), anyString());
    }

    @Test
    public void testUserNotCreatedIsSkipped() throws Exception {

        // For example, the registration is pending approval.
        FlowExecutionContext context = registrationContext();
        context.getFlowUser().setUserId(null);

        assertTrue(listener.doPostExecute(step("COMPLETE"), context));

        verify(client, never()).identifyUser(anyString(), anyString());
    }

    @Test
    public void testIdentifyFailureDoesNotFailFlow() throws Exception {

        when(client.identifyUser(anyString(), anyString())).thenThrow(new AuthsignalClientException("down", 500));

        assertTrue(listener.doPostExecute(step("COMPLETE"), registrationContext()));
        assertNull(claimUpdates.getClaims());
    }

    @Test
    public void testMissingSecretDoesNotFailFlow() throws Exception {

        tenantProperties.remove(AuthsignalConnectorConfig.SECRET_KEY);

        assertTrue(listener.doPostExecute(step("COMPLETE"), registrationContext()));
        verify(client, never()).identifyUser(anyString(), anyString());
    }

    private static FlowExecutionStep step(String status) {

        FlowExecutionStep step = new FlowExecutionStep();
        step.setFlowStatus(status);
        return step;
    }

    private static FlowExecutionContext registrationContext() {

        FlowUser flowUser = new FlowUser();
        flowUser.setUsername("jane");
        flowUser.setUserStoreDomain("PRIMARY");
        flowUser.setUserId(USER_UUID);
        FlowExecutionContext context = new FlowExecutionContext();
        context.setFlowType(AuthsignalExecutor.REGISTRATION);
        context.setTenantDomain(TENANT);
        context.setContextIdentifier("flow-1");
        context.setFlowUser(flowUser);
        context.setProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID, "challenge-1");
        return context;
    }

    private static FlowResponse identified(String email, String phoneNumber) {

        FlowResponse.Authenticator emailOtp = new FlowResponse.Authenticator();
        emailOtp.setVerificationMethod("EMAIL_OTP");
        emailOtp.setEmail(email);
        FlowResponse.Authenticator sms = new FlowResponse.Authenticator();
        sms.setVerificationMethod("SMS");
        sms.setPhoneNumber(phoneNumber);
        FlowResponse.User user = new FlowResponse.User();
        user.setUserId(USER_UUID);
        user.setAuthenticators(Arrays.asList(emailOtp, sms));
        FlowResponse response = new FlowResponse();
        response.setUser(user);
        return response;
    }

    private class TestableListener extends AuthsignalFlowExecutionListener {

        @Override
        protected AuthsignalConfig resolveConfig(String tenantDomain) {

            return new AuthsignalConfig(tenantProperties);
        }

        @Override
        protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalClientException {

            super.createClient(config);
            return client;
        }
    }

    /**
     * Detects whether the sync is disabled by running a sync that would otherwise call Authsignal.
     */
    private class AuthsignalUserOperationEventListenerProbe extends AuthsignalUserOperationEventListener {

        private boolean called;

        boolean isSyncDisabled() {

            syncContactDetails("jane", null, Map.of(AuthsignalConstants.EMAIL_CLAIM, EMAIL));
            return !called;
        }

        @Override
        protected String getTenantDomain(org.wso2.carbon.user.core.UserStoreManager userStoreManager) {

            called = true;
            return TENANT;
        }

        @Override
        protected AuthsignalConfig resolveConfig(String tenantDomain) {

            // Stop the probe here: only whether the sync started matters.
            throw new IllegalStateException("probe");
        }
    }
}
