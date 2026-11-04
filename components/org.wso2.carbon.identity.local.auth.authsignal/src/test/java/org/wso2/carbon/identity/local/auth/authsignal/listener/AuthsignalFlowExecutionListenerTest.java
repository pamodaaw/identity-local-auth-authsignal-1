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

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowContextProps;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowType;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalConnectionException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalResponse;
import org.wso2.carbon.identity.local.auth.authsignal.util.ClaimUpdateRecorder;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
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

    private MockedStatic<LoggerUtils> loggerUtils;
    private AuthsignalClient client;
    private Map<String, String> tenantProperties;
    private TestableListener listener;
    private ClaimUpdateRecorder claimUpdates;

    @BeforeMethod
    public void setUp() {

        // Diagnostic logs are disabled, as they need a running server.
        loggerUtils = mockStatic(LoggerUtils.class);
        client = mock(AuthsignalClient.class);
        tenantProperties = new HashMap<>();
        tenantProperties.put(ConnectorConfig.SECRET_KEY, "secret");
        tenantProperties.put(ConnectorConfig.PASSKEY_ENROLLED_CLAIM, PASSKEY_CLAIM);
        listener = new TestableListener();
        claimUpdates = ClaimUpdateRecorder.start();
    }

    @AfterMethod
    public void tearDown() {

        loggerUtils.close();
        claimUpdates.close();
    }

    @Test
    public void testCompletedRegistrationIdentifiesUserAndMarksContactDetailsVerified() throws Exception {

        FlowExecutionContext context = withContactDetails(registrationContext(), EMAIL, MOBILE);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(
                authenticator("EMAIL_OTP", "Jane@Example.com", null), authenticator("SMS", null, MOBILE)));

        assertTrue(listener.doPostExecute(step("COMPLETE"), context));

        verify(client).identifyUser(USER_UUID, "challenge-1");
        // The primary user store domain is implicit.
        assertEquals(claimUpdates.getUsername(), "jane");
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.EMAIL_VERIFIED_CLAIM), "true");
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.MOBILE_VERIFIED_CLAIM), "true");
        assertEquals(claimUpdates.getClaims().get(PASSKEY_CLAIM), "false");
        assertFalse(claimUpdates.getClaims().containsKey(AuthsignalConstants.EMAIL_CLAIM),
                "The user's own email address is kept");
        assertFalse(claimUpdates.getClaims().containsKey(AuthsignalConstants.MOBILE_CLAIM),
                "The user's own mobile number is kept");
        assertNull(context.getProperty(FlowContextProps.CHALLENGE_ID), "Identify runs once");
    }

    @Test
    public void testOnlyValuesVerifiedOnAuthsignalAreMarked() throws Exception {

        FlowExecutionContext context = withContactDetails(registrationContext(), EMAIL, MOBILE);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(
                authenticator("EMAIL_OTP", EMAIL, null)));

        listener.doPostExecute(step("COMPLETE"), context);

        assertEquals(claimUpdates.getClaims().size(), 2);
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.EMAIL_VERIFIED_CLAIM), "true");
        assertEquals(claimUpdates.getClaims().get(PASSKEY_CLAIM), "false");
    }

    @Test
    public void testPasskeyOnlyUserMarksNothingVerified() throws Exception {

        FlowExecutionContext context = withContactDetails(registrationContext(), EMAIL, null);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(
                authenticator("PASSKEY", null, null)));

        listener.doPostExecute(step("COMPLETE"), context);

        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "true"));
    }

    @Test
    public void testValueDifferentFromUserIsNotMarkedVerified() throws Exception {

        FlowExecutionContext context = withContactDetails(registrationContext(), "other@example.com", MOBILE);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(
                authenticator("EMAIL_OTP", EMAIL, null), authenticator("SMS", null, MOBILE)));

        listener.doPostExecute(step("COMPLETE"), context);

        assertFalse(claimUpdates.getClaims().containsKey(AuthsignalConstants.EMAIL_VERIFIED_CLAIM));
        assertFalse(claimUpdates.getClaims().containsKey(AuthsignalConstants.EMAIL_CLAIM));
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.MOBILE_VERIFIED_CLAIM), "true");
    }

    @Test
    public void testOnlyAuthenticatorsOfCompletedStepsAreMarked() throws Exception {

        FlowExecutionContext context = withContactDetails(registrationContext(), EMAIL, MOBILE);
        AuthsignalResponse.Authenticator email = authenticator("EMAIL_OTP", EMAIL, null);
        AuthsignalResponse response = identified(email);
        response.getUser().setAuthenticators(Arrays.asList(email, authenticator("SMS", null, MOBILE),
                authenticator("PASSKEY", null, null)));
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(response);

        listener.doPostExecute(step("COMPLETE"), context);

        assertEquals(claimUpdates.getClaims().size(), 2);
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.EMAIL_VERIFIED_CLAIM), "true");
        assertEquals(claimUpdates.getClaims().get(PASSKEY_CLAIM), "false");
    }

    @Test
    public void testAuthenticatorsAreMarkedWithoutCompletedSteps() throws Exception {

        // Identify User returns the user's authenticators without the completed steps.
        FlowExecutionContext context = withContactDetails(registrationContext(), EMAIL, MOBILE);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(enrolled(
                authenticator("EMAIL_OTP", EMAIL, null), authenticator("WHATSAPP", null, MOBILE),
                authenticator("AUTHENTICATOR_APP", null, null)));

        listener.doPostExecute(step("COMPLETE"), context);

        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.EMAIL_VERIFIED_CLAIM), "true");
        assertEquals(claimUpdates.getClaims().get(AuthsignalConstants.MOBILE_VERIFIED_CLAIM), "true");
        assertEquals(claimUpdates.getClaims().get(PASSKEY_CLAIM), "false");
    }

    @Test
    public void testPasskeyEnrolledIsNotSavedWithoutConfiguredClaim() throws Exception {

        tenantProperties.remove(ConnectorConfig.PASSKEY_ENROLLED_CLAIM);
        FlowExecutionContext context = withContactDetails(registrationContext(), EMAIL, null);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified(
                authenticator("EMAIL_OTP", EMAIL, null), authenticator("PASSKEY", null, null)));

        listener.doPostExecute(step("COMPLETE"), context);

        assertEquals(claimUpdates.getClaims(),
                Collections.singletonMap(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, "true"));
    }

    @Test
    public void testNothingSavedWithoutVerifiedValuesOrConfiguredClaim() throws Exception {

        tenantProperties.remove(ConnectorConfig.PASSKEY_ENROLLED_CLAIM);
        when(client.identifyUser(USER_UUID, "challenge-1")).thenReturn(identified());

        listener.doPostExecute(step("COMPLETE"), registrationContext());

        assertNull(claimUpdates.getClaims());
    }

    @Test
    public void testIncompleteFlowIsIgnored() throws Exception {

        FlowExecutionContext context = registrationContext();

        assertTrue(listener.doPostExecute(step("INCOMPLETE"), context));

        verify(client, never()).identifyUser(anyString(), anyString());
        assertEquals(context.getProperty(FlowContextProps.CHALLENGE_ID), "challenge-1");
    }

    @Test
    public void testOtherFlowTypesAreIgnored() throws Exception {

        FlowExecutionContext context = registrationContext();
        context.setFlowType(FlowType.PASSWORD_RECOVERY);

        listener.doPostExecute(step("COMPLETE"), context);

        verify(client, never()).identifyUser(anyString(), anyString());
    }

    @Test
    public void testRegistrationWithoutAuthsignalIsIgnored() throws Exception {

        FlowExecutionContext context = registrationContext();
        context.getProperties().remove(FlowContextProps.CHALLENGE_ID);

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
    public void testPendingLinkIsSavedOnTransientFailure() throws Exception {

        when(client.identifyUser(anyString(), anyString())).thenThrow(new AuthsignalConnectionException("down", 503));

        assertTrue(listener.doPostExecute(step("COMPLETE"),
                withContactDetails(registrationContext(), EMAIL, null)));

        // Not retried in the flow; the link is completed at the next sign-in.
        verify(client, times(1)).identifyUser(USER_UUID, "challenge-1");
        assertEquals(claimUpdates.getUsername(), "jane");
        // The verified claims are saved only once the link succeeds.
        assertEquals(claimUpdates.getClaims(),
                Collections.singletonMap(AuthsignalConstants.CHALLENGE_ID_CLAIM, "challenge-1"));
    }

    @Test
    public void testRejectedLinkIsNotRetried() throws Exception {

        when(client.identifyUser(anyString(), anyString()))
                .thenThrow(new AuthsignalConnectionException("expired", 400));

        assertTrue(listener.doPostExecute(step("COMPLETE"),
                withContactDetails(registrationContext(), EMAIL, null)));

        verify(client, times(1)).identifyUser(USER_UUID, "challenge-1");
        assertNull(claimUpdates.getClaims(), "Nothing is saved when the link fails");
    }

    @Test
    public void testPendingLinkSaveFailureDoesNotFailFlow() throws Exception {

        when(client.identifyUser(anyString(), anyString())).thenThrow(new AuthsignalConnectionException("down"));
        claimUpdates.failWith(new UserStoreException("store down"));

        assertTrue(listener.doPostExecute(step("COMPLETE"), registrationContext()));
    }

    @Test
    public void testMissingSecretDoesNotFailFlow() throws Exception {

        tenantProperties.remove(ConnectorConfig.SECRET_KEY);

        assertTrue(listener.doPostExecute(step("COMPLETE"), registrationContext()));
        verify(client, never()).identifyUser(anyString(), anyString());
        assertNull(claimUpdates.getClaims(), "A configuration error is not retried at sign-in");
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
        context.setFlowType(FlowType.REGISTRATION);
        context.setTenantDomain(TENANT);
        context.setContextIdentifier("flow-1");
        context.setFlowUser(flowUser);
        context.setProperty(FlowContextProps.CHALLENGE_ID, "challenge-1");
        return context;
    }

    /**
     * Set the email address and mobile number on the user.
     */
    private static FlowExecutionContext withContactDetails(FlowExecutionContext context, String email,
                                                           String mobile) {

        if (email != null) {
            context.getFlowUser().addClaim(AuthsignalConstants.EMAIL_CLAIM, email);
        }
        if (mobile != null) {
            context.getFlowUser().addClaim(AuthsignalConstants.MOBILE_CLAIM, mobile);
        }
        return context;
    }

    private static AuthsignalResponse.Authenticator authenticator(String method, String email, String phoneNumber) {

        AuthsignalResponse.Authenticator authenticator = new AuthsignalResponse.Authenticator();
        authenticator.setUserAuthenticatorId(method);
        authenticator.setVerificationMethod(method);
        authenticator.setEmail(email);
        authenticator.setPhoneNumber(phoneNumber);
        return authenticator;
    }

    /**
     * Build an Identify User response with the user's authenticators, each verified in the registration flow.
     */
    private static AuthsignalResponse identified(AuthsignalResponse.Authenticator... authenticators) {

        AuthsignalResponse response = enrolled(authenticators);
        List<AuthsignalResponse.Step> steps = new ArrayList<>();
        for (AuthsignalResponse.Authenticator authenticator : authenticators) {
            AuthsignalResponse.Step step = new AuthsignalResponse.Step();
            step.setStepType("ENROLLMENT_REQUIRED");
            step.setVerificationMethod(authenticator.getVerificationMethod());
            step.setUserAuthenticatorId(authenticator.getUserAuthenticatorId());
            steps.add(step);
        }
        response.getAction().setCompletedSteps(steps);
        return response;
    }

    /**
     * Build an Identify User response with the user's authenticators and no completed steps.
     */
    private static AuthsignalResponse enrolled(AuthsignalResponse.Authenticator... authenticators) {

        AuthsignalResponse.User user = new AuthsignalResponse.User();
        user.setUserId(USER_UUID);
        user.setAuthenticators(Arrays.asList(authenticators));
        AuthsignalResponse response = new AuthsignalResponse();
        response.setAction(new AuthsignalResponse.Action());
        response.setUser(user);
        return response;
    }

    private class TestableListener extends AuthsignalFlowExecutionListener {

        @Override
        protected AuthsignalConfig resolveConfig(String tenantDomain) {

            return new AuthsignalConfig(tenantProperties);
        }

        @Override
        protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalConnectionException {

            super.createClient(config);
            return client;
        }
    }
}
