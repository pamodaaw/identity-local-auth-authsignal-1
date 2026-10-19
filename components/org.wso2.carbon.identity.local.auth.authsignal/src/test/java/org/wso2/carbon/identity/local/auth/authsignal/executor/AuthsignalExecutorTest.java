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

package org.wso2.carbon.identity.local.auth.authsignal.executor;

import org.mockito.ArgumentCaptor;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.flow.execution.engine.graph.AuthenticationExecutor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.FlowResponse;
import org.wso2.carbon.identity.local.auth.authsignal.model.StartFlowRequest;
import org.wso2.carbon.identity.local.auth.authsignal.util.ClaimUpdateRecorder;
import org.wso2.carbon.user.api.UserStoreException;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Tests for {@link AuthsignalExecutor}.
 */
public class AuthsignalExecutorTest {

    private static final String TENANT = "carbon.super";
    private static final String PORTAL_URL = "https://localhost:9443/accounts/register?flowType=REGISTRATION";
    private static final String CHALLENGE_URL = "https://signin.authsignal.com/challenge";
    private static final String USER_UUID = "8f1c1c0e-3a3b-4d3a-9a51-111111111111";
    private static final String EMAIL = "alice@example.com";
    private static final String MOBILE = "+94770000000";
    private static final String PASSKEY_CLAIM = "http://wso2.org/claims/authsignalPasskeyEnrolled";

    private AuthsignalClient client;
    private Map<String, String> tenantProperties;
    private String storeUserId;
    private ClaimUpdateRecorder claimUpdates;
    private TestableExecutor executor;

    @AfterMethod
    public void tearDown() {

        claimUpdates.close();
    }

    @BeforeMethod
    public void setUp() {

        client = mock(AuthsignalClient.class);
        tenantProperties = new HashMap<>();
        tenantProperties.put(AuthsignalConnectorConfig.SECRET_KEY, "secret");
        tenantProperties.put(AuthsignalConnectorConfig.PASSKEY_ENROLLED_CLAIM, PASSKEY_CLAIM);
        storeUserId = USER_UUID;
        claimUpdates = ClaimUpdateRecorder.start();
        executor = new TestableExecutor();
    }

    @Test
    public void testMetadata() {

        assertEquals(executor.getName(), "AuthsignalExecutor");
        // The flow management API reports requiresConnection = true for authentication executors and executors with
        // an associated authenticator, which makes the Console ask for a connection.
        assertFalse(AuthenticationExecutor.class.isAssignableFrom(AuthsignalExecutor.class));
        assertNull(executor.getExecutorMetadata().getAssociatedAuthenticator());
        assertFalse(executor.getExecutorMetadata().isConnectionRequired());
        assertTrue(executor.getSupportedFlowTypes().contains(FlowTypes.REGISTRATION));
        assertTrue(executor.getSupportedFlowTypes().contains(FlowTypes.PASSWORD_RECOVERY));
        assertTrue(executor.getSupportedFlowTypes().contains(FlowTypes.INVITED_USER_REGISTRATION));
        // Supported once the framework defines the flow type.
        for (FlowTypes flowType : FlowTypes.values()) {
            if (AuthsignalExecutor.SECURED_SELF_SERVICE_OPERATIONS.equals(flowType.name())) {
                assertTrue(executor.getSupportedFlowTypes().contains(flowType));
            }
        }
        assertTrue(executor.getInitiationData().isEmpty());
    }

    @Test
    public void testRegistrationStartsFlowWithEmailAndPhoneHint() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "EXTERNAL_REDIRECTION");
        assertEquals(response.getAdditionalInfo().get("redirectUrl"), CHALLENGE_URL);
        String state = response.getAdditionalInfo().get("state");
        assertNotNull(state);
        assertTrue(response.getRequiredData().contains("code"));
        assertTrue(response.getRequiredData().contains("state"));
        assertTrue(response.getRequiredData().contains("challenge_token"));

        StartFlowRequest request = captureStartRequest();
        assertEquals(request.getActionCode(), "sign-up");
        assertNull(request.getUserId(), "The WSO2 user does not exist yet");
        assertEquals(request.getUserEmail(), EMAIL);
        assertNull(request.getUserPhoneNumber(), "Authsignal takes one user identifier only");
        assertEquals(request.getHintPhoneNumber(), MOBILE);
        assertEquals(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_PENDING_CHALLENGE_ID), "challenge-1");

        // The portal resumes the flow with the code and state the executor put in the redirect URL.
        Map<String, String> query = query(request.getRedirectUrl());
        assertTrue(request.getRedirectUrl().startsWith(PORTAL_URL + "&"));
        assertEquals(query.get("state"), state);
        assertEquals(query.get("code"), context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CODE));
    }

    @Test
    public void testRegistrationWithoutEmailStartsFlowWithPhone() throws Exception {

        when(client.startFlow(any())).thenReturn(started());

        executor.execute(registrationContext(null, MOBILE));

        StartFlowRequest request = captureStartRequest();
        assertEquals(request.getUserPhoneNumber(), MOBILE);
        assertNull(request.getUserEmail());
        assertNull(request.getHintPhoneNumber());
    }

    @Test
    public void testRegistrationSkipsNonE164Mobile() throws Exception {

        when(client.startFlow(any())).thenReturn(started());

        executor.execute(registrationContext(EMAIL, "0770000000"));

        assertNull(captureStartRequest().getHintPhoneNumber());
    }

    @Test
    public void testRegistrationWithoutContactDetailsFails() throws Exception {

        ExecutorResponse response = executor.execute(registrationContext(null, "0770000000"));

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_CONTACT_DETAILS_NOT_FOUND.getCode());
        verify(client, never()).startFlow(any());
    }

    @Test
    public void testRegistrationWithoutChallengeIdFails() throws Exception {

        FlowResponse startResponse = started();
        startResponse.setChallengeId(null);
        when(client.startFlow(any())).thenReturn(startResponse);

        ExecutorResponse response = executor.execute(registrationContext(EMAIL, MOBILE));

        assertEquals(response.getResult(), "ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_START_FLOW_FAILED.getCode());
    }

    @Test
    public void testConfiguredRegistrationFlowRef() throws Exception {

        tenantProperties.put(AuthsignalConnectorConfig.REGISTRATION_FLOW_REF, "custom-sign-up");
        when(client.startFlow(any())).thenReturn(started());

        executor.execute(registrationContext(EMAIL, MOBILE));

        assertEquals(captureStartRequest().getActionCode(), "custom-sign-up");
    }

    @Test
    public void testRegistrationCallbackCompletesAndKeepsChallengeId() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-up", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED"), authenticator("EMAIL_OTP", "Alice@Example.com", null)));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "COMPLETE");
        assertEquals(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID), "challenge-1");
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_STATE), "Flow must be consumed");
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_PENDING_CHALLENGE_ID));
        assertEquals(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_PASSKEY_ENROLLED), Boolean.FALSE);
        assertNull(claimUpdates.getClaims(), "The user does not exist yet");
    }

    @Test
    public void testRegistrationCallbackKeepsPasskeyEnrolledInFlow() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-up", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED"), step("ENROLLMENT_REQUIRED", "PASSKEY"),
                authenticator("EMAIL_OTP", EMAIL, null)));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
        assertEquals(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_PASSKEY_ENROLLED), Boolean.TRUE);
        assertNull(claimUpdates.getClaims());
    }

    @Test
    public void testRegistrationCallbackWithAnotherVerifiedEmailFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-up", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED"), authenticator("EMAIL_OTP", "mallory@example.com", null)));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH.getCode());
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID));
    }

    @Test
    public void testPhoneRegistrationCallbackBindsToVerifiedPhone() throws Exception {

        FlowExecutionContext context = registrationContext(null, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-up", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "temp-id",
                step("VERIFICATION_REQUIRED"), authenticator("SMS", null, MOBILE)));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
    }

    @Test
    public void testFailedFlowFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-up", "tok")).thenReturn(verified("CHALLENGE_FAILED", "temp-id",
                step("VERIFICATION_REQUIRED"), authenticator("EMAIL_OTP", EMAIL, null)));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_CHALLENGE_NOT_SUCCEEDED.getCode());
    }

    @Test
    public void testCallbackWithWrongStateFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        executor.execute(context);
        context.addUserInputData("code", (String) context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CODE));
        context.addUserInputData("state", "forged-state");
        context.addUserInputData("challenge_token", "tok");

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_INVALID_CALLBACK.getCode());
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_STATE), "A forged callback consumes the flow");
        verify(client, never()).verifyFlow(anyString(), anyString());
    }

    @Test
    public void testCallbackWithoutChallengeTokenFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        context.addUserInputData("code", (String) context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CODE));
        context.addUserInputData("state", redirect.getAdditionalInfo().get("state"));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(), AuthsignalConstants.ErrorMessages.ERROR_CODE_MISSING_TOKEN.getCode());
        verify(client, never()).verifyFlow(anyString(), anyString());
    }

    @Test
    public void testRecoveryStartsFlowWithUserId() throws Exception {

        when(client.startFlow(any())).thenReturn(started());

        ExecutorResponse response = executor.execute(recoveryContext());

        assertEquals(response.getResult(), "EXTERNAL_REDIRECTION");
        StartFlowRequest request = captureStartRequest();
        assertEquals(request.getActionCode(), "password-reset");
        assertEquals(request.getUserId(), USER_UUID);
        assertNull(request.getUserEmail());
        assertNull(request.getHintEmail());
    }

    @Test
    public void testRecoveryUsesUserStoreLookupWhenUserIdMissing() throws Exception {

        FlowExecutionContext context = recoveryContext();
        context.getFlowUser().setUserId(null);
        storeUserId = "looked-up-id";
        when(client.startFlow(any())).thenReturn(started());

        executor.execute(context);

        assertEquals(captureStartRequest().getUserId(), "looked-up-id");
    }

    @Test
    public void testRecoveryForUnknownUserFails() throws Exception {

        FlowExecutionContext context = recoveryContext();
        context.getFlowUser().setUserId(null);
        storeUserId = null;

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_USER_NOT_IDENTIFIED.getCode());
        verify(client, never()).startFlow(any());
    }

    @Test
    public void testRecoveryUsernameIdentifier() throws Exception {

        tenantProperties.put(AuthsignalConnectorConfig.USER_IDENTIFIER, "username");
        when(client.startFlow(any())).thenReturn(started());

        executor.execute(recoveryContext());

        assertEquals(captureStartRequest().getUserId(), "alice");
    }

    @Test
    public void testRecoveryCallbackCompletes() throws Exception {

        FlowExecutionContext context = recoveryContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("password-reset", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED")));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "COMPLETE");
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID));
    }

    @Test
    public void testRecoveryCallbackForAnotherUserFails() throws Exception {

        FlowExecutionContext context = recoveryContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("password-reset", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "someone",
                step("VERIFICATION_REQUIRED")));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH.getCode());
    }

    @Test
    public void testRecoveryWithEnrolmentFails() throws Exception {

        // Whoever started the recovery must not pass it by enrolling their own authenticator.
        FlowExecutionContext context = recoveryContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("password-reset", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("ENROLLMENT_REQUIRED")));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_USER_NOT_ENROLLED.getCode());
    }

    @Test
    public void testRecoveryWithoutCompletedStepsFails() throws Exception {

        FlowExecutionContext context = recoveryContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("password-reset", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID));

        assertEquals(executor.execute(context).getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_USER_NOT_ENROLLED.getCode());
    }

    @Test
    public void testInvitedUserRegistrationStartsRegistrationFlowWithUserId() throws Exception {

        FlowUser flowUser = existingUser();
        when(client.startFlow(any())).thenReturn(started());

        executor.execute(context(AuthsignalExecutor.INVITED_USER_REGISTRATION, flowUser));

        StartFlowRequest request = captureStartRequest();
        assertEquals(request.getActionCode(), "sign-up");
        assertEquals(request.getUserId(), USER_UUID);
    }

    @Test
    public void testSelfServiceStartsSignInFlowWithUserId() throws Exception {

        when(client.startFlow(any())).thenReturn(started());

        ExecutorResponse response = executor.execute(selfServiceContext());

        assertEquals(response.getResult(), "EXTERNAL_REDIRECTION");
        StartFlowRequest request = captureStartRequest();
        assertEquals(request.getActionCode(), "sign-in");
        assertEquals(request.getUserId(), USER_UUID);
        assertNull(request.getUserEmail());
    }

    @Test
    public void testConfiguredSignInFlowRefUsedForSelfService() throws Exception {

        tenantProperties.put(AuthsignalConnectorConfig.SIGN_IN_FLOW_REF, "custom-sign-in");
        when(client.startFlow(any())).thenReturn(started());

        executor.execute(selfServiceContext());

        assertEquals(captureStartRequest().getActionCode(), "custom-sign-in");
    }

    @Test
    public void testSelfServiceCallbackCompletes() throws Exception {

        FlowExecutionContext context = selfServiceContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED")));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "COMPLETE");
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_STATE), "Flow must be consumed");
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID));
        assertEquals(claimUpdates.getUsername(), "alice");
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "false"));
    }

    @Test
    public void testPasskeyEnrolledIsNotSavedWithoutConfiguredClaim() throws Exception {

        tenantProperties.remove(AuthsignalConnectorConfig.PASSKEY_ENROLLED_CLAIM);
        FlowExecutionContext context = selfServiceContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED", "PASSKEY")));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
        assertNull(claimUpdates.getClaims());
    }

    @Test
    public void testSelfServiceCallbackSavesPasskeyEnrolledWhenUserHasPasskey() throws Exception {

        FlowExecutionContext context = selfServiceContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED"), authenticator("PASSKEY", null, null)));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "true"));
    }

    @Test
    public void testSelfServiceCallbackSavesPasskeyEnrolledWhenVerifiedWithPasskey() throws Exception {

        FlowExecutionContext context = selfServiceContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED", "PASSKEY")));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
        assertEquals(claimUpdates.getClaims(), Collections.singletonMap(PASSKEY_CLAIM, "true"));
    }

    @Test
    public void testFailureToSavePasskeyEnrolledDoesNotFailFlow() throws Exception {

        claimUpdates.failWith(new UserStoreException("Claim not found"));
        FlowExecutionContext context = selfServiceContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED", "PASSKEY")));

        assertEquals(executor.execute(context).getResult(), "COMPLETE");
    }

    @Test
    public void testSelfServiceCallbackForAnotherUserFails() throws Exception {

        FlowExecutionContext context = selfServiceContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", "someone",
                step("VERIFICATION_REQUIRED")));

        assertEquals(executor.execute(context).getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_CHALLENGE_MISMATCH.getCode());
    }

    @Test
    public void testSelfServiceWithEnrolmentFails() throws Exception {

        // Whoever holds the user's session must not pass the verification by enrolling their own authenticator.
        FlowExecutionContext context = selfServiceContext();
        when(client.startFlow(any())).thenReturn(started());
        ExecutorResponse redirect = executor.execute(context);
        callback(context, redirect);
        when(client.verifyFlow("sign-in", "tok")).thenReturn(verified("CHALLENGE_SUCCEEDED", USER_UUID,
                step("VERIFICATION_REQUIRED"), step("ENROLLMENT_OPTIONAL")));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_USER_NOT_ENROLLED.getCode());
    }

    @Test
    public void testSelfServiceForUnknownUserFails() throws Exception {

        FlowExecutionContext context = selfServiceContext();
        context.getFlowUser().setUserId(null);
        storeUserId = null;

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), "USER_ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_USER_NOT_IDENTIFIED.getCode());
        verify(client, never()).startFlow(any());
    }

    @Test
    public void testMissingSecretFails() throws Exception {

        tenantProperties.remove(AuthsignalConnectorConfig.SECRET_KEY);

        ExecutorResponse response = executor.execute(registrationContext(EMAIL, MOBILE));

        assertEquals(response.getResult(), "ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_SECRET_KEY_NOT_CONFIGURED.getCode());
    }

    @Test
    public void testMissingPortalUrlFails() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        context.setPortalUrl(null);

        assertEquals(executor.execute(context).getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_PORTAL_URL_NOT_FOUND.getCode());
    }

    @Test
    public void testUnsupportedFlowTypeFails() throws Exception {

        ExecutorResponse response = executor.execute(context("ASK_PASSWORD", existingUser()));

        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_FLOW_TYPE.getCode());
    }

    @Test
    public void testStartFlowFailure() throws Exception {

        when(client.startFlow(any())).thenThrow(new AuthsignalClientException("down", 500));

        ExecutorResponse response = executor.execute(registrationContext(EMAIL, MOBILE));

        assertEquals(response.getResult(), "ERROR");
        assertEquals(response.getErrorCode(),
                AuthsignalConstants.ErrorMessages.ERROR_CODE_START_FLOW_FAILED.getCode());
    }

    @Test
    public void testRollbackClearsFlowState() throws Exception {

        FlowExecutionContext context = registrationContext(EMAIL, MOBILE);
        when(client.startFlow(any())).thenReturn(started());
        executor.execute(context);
        context.setProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID, "challenge-1");

        executor.rollback(context);

        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_STATE));
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_PENDING_CHALLENGE_ID));
        assertNull(context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID));
    }

    @Test
    public void testBuildRedirectUrl() {

        assertEquals(AuthsignalExecutor.buildRedirectUrl("https://p/register", "c", "s"),
                "https://p/register?code=c&state=s");
        assertEquals(AuthsignalExecutor.buildRedirectUrl("https://p/register?a=b#frag", "c", "s"),
                "https://p/register?a=b&code=c&state=s");
    }

    private StartFlowRequest captureStartRequest() throws Exception {

        ArgumentCaptor<StartFlowRequest> captor = ArgumentCaptor.forClass(StartFlowRequest.class);
        verify(client).startFlow(captor.capture());
        return captor.getValue();
    }

    private FlowExecutionContext registrationContext(String email, String mobile) {

        FlowUser flowUser = new FlowUser();
        if (email != null) {
            flowUser.addClaim(AuthsignalConstants.EMAIL_CLAIM, email);
        }
        if (mobile != null) {
            flowUser.addClaim(AuthsignalConstants.MOBILE_CLAIM, mobile);
        }
        return context(AuthsignalExecutor.REGISTRATION, flowUser);
    }

    private FlowExecutionContext recoveryContext() {

        return context(AuthsignalExecutor.PASSWORD_RECOVERY, existingUser());
    }

    private FlowExecutionContext selfServiceContext() {

        return context(AuthsignalExecutor.SECURED_SELF_SERVICE_OPERATIONS, existingUser());
    }

    private static FlowUser existingUser() {

        FlowUser flowUser = new FlowUser();
        flowUser.setUsername("alice");
        flowUser.setUserStoreDomain("PRIMARY");
        flowUser.setUserId(USER_UUID);
        flowUser.addClaim(AuthsignalConstants.EMAIL_CLAIM, EMAIL);
        return flowUser;
    }

    private static FlowExecutionContext context(String flowType, FlowUser flowUser) {

        FlowExecutionContext context = new FlowExecutionContext();
        context.setFlowType(flowType);
        context.setTenantDomain(TENANT);
        context.setPortalUrl(PORTAL_URL);
        context.setFlowUser(flowUser);
        return context;
    }

    /**
     * Simulate the portal resuming the flow with the code and state from the redirect URL and the challenge token
     * Authsignal appended to it.
     */
    private static void callback(FlowExecutionContext context, ExecutorResponse redirect) {

        context.addUserInputData("code", (String) context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CODE));
        context.addUserInputData("state", redirect.getAdditionalInfo().get("state"));
        context.addUserInputData("challenge_token", "tok");
    }

    private static FlowResponse started() {

        FlowResponse response = new FlowResponse();
        response.setChallengeUrl(CHALLENGE_URL);
        response.setChallengeId("challenge-1");
        response.setChallengeToken("start-token");
        return response;
    }

    private static FlowResponse.Step step(String stepType) {

        return step(stepType, "EMAIL_OTP");
    }

    private static FlowResponse.Step step(String stepType, String verificationMethod) {

        FlowResponse.Step step = new FlowResponse.Step();
        step.setStepType(stepType);
        step.setVerificationMethod(verificationMethod);
        return step;
    }

    private static FlowResponse.Authenticator authenticator(String method, String email, String phoneNumber) {

        FlowResponse.Authenticator authenticator = new FlowResponse.Authenticator();
        authenticator.setVerificationMethod(method);
        authenticator.setEmail(email);
        authenticator.setPhoneNumber(phoneNumber);
        return authenticator;
    }

    private static FlowResponse verified(String state, String userId, Object... stepsAndAuthenticators) {

        List<FlowResponse.Step> steps = new ArrayList<>();
        List<FlowResponse.Authenticator> authenticators = new ArrayList<>();
        for (Object item : stepsAndAuthenticators) {
            if (item instanceof FlowResponse.Step) {
                steps.add((FlowResponse.Step) item);
            } else {
                authenticators.add((FlowResponse.Authenticator) item);
            }
        }
        FlowResponse.Action action = new FlowResponse.Action();
        action.setState(state);
        action.setCompletedSteps(steps);
        FlowResponse.User user = new FlowResponse.User();
        user.setUserId(userId);
        user.setAuthenticators(authenticators);
        FlowResponse response = new FlowResponse();
        response.setAction(action);
        response.setUser(user);
        return response;
    }

    private static Map<String, String> query(String url) {

        Map<String, String> params = new HashMap<>();
        for (String pair : URI.create(url).getQuery().split("&")) {
            String[] kv = pair.split("=", 2);
            params.put(kv[0], kv.length > 1 ? kv[1] : "");
        }
        return params;
    }

    /**
     * Replaces the server runtime dependencies (tenant configuration, user store, HTTP client) with test doubles.
     */
    private class TestableExecutor extends AuthsignalExecutor {

        @Override
        protected AuthsignalConfig resolveConfig(String tenantDomain) {

            return new AuthsignalConfig(tenantProperties);
        }

        @Override
        protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalClientException {

            super.createClient(config);
            return client;
        }

        @Override
        protected String getUserId(String tenantDomain, String userStoreDomain, String username) {

            return storeUserId;
        }
    }
}
