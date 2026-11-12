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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.flow.mgt.model.ExecutorDTO;
import org.wso2.carbon.identity.flow.mgt.model.NodeConfig;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ActionState;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ExecutorErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ExecutorMetadata;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowContextProps;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowType;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.InputKeys;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.Messages;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.RequestParams;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalConnectionException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalResponse;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalDiagnosticLogUtil;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ErrorMessages.ERROR_CODE_EXECUTOR_FAILURE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.REDIRECT_URL;
import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.ActionIDs.START_AUTHSIGNAL_FLOW;
import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.ActionIDs.VERIFY_AUTHSIGNAL_FLOW;

/**
 * Flow executor that verifies the user with Authsignal.
 * <p>
 * In registration, the user does not exist yet, so the flow is started with the user's email address or mobile
 * number. {@link org.wso2.carbon.identity.local.auth.authsignal.listener.AuthsignalFlowExecutionListener} links the
 * Authsignal user to the new WSO2 user afterwards.
 */
public class AuthsignalExecutor implements Executor {

    private static final Log LOG = LogFactory.getLog(AuthsignalExecutor.class);
    private static final String USER_ID_DESCRIPTION = "%s User ID: %s";
    private static final String ICON = loadIcon();

    @Override
    public String getName() {

        return AuthsignalConstants.EXECUTOR_NAME;
    }

    @Override
    public Set<FlowTypes> getSupportedFlowTypes() {

        return EnumSet.of(FlowTypes.REGISTRATION, FlowTypes.INVITED_USER_REGISTRATION, FlowTypes.PASSWORD_RECOVERY);
    }

    @Override
    public FlowExecutorMetadata getExecutorMetadata() {

        return FlowExecutorMetadata.builder()
                .displayName(AuthsignalConstants.EXECUTOR_DISPLAY_NAME)
                .icon(ICON)
                .build();
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) throws FlowEngineException {

        if (isFlowCallback(context)) {
            return processFlowResult(context);
        }
        return startFlow(context);
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        return null;
    }

    /**
     * Start the Authsignal flow of the flow type and redirect the user to the pre-built UI.
     */
    private ExecutorResponse startFlow(FlowExecutionContext context) throws FlowEngineServerException {

        String flowType = context.getFlowType();
        // The portal URL is needed to handle the redirection from Authsignal.
        String portalUrl = context.getPortalUrl();
        if (StringUtils.isBlank(portalUrl)) {
            throw serverException(ExecutorErrorMessages.PORTAL_URL_NOT_FOUND, null, null);
        }

        AuthsignalConfig config;
        try {
            config = resolveConfig(context.getTenantDomain());
        } catch (IdentityGovernanceException e) {
            throw serverException(ExecutorErrorMessages.READING_CONFIG, null, e);
        }
        if (StringUtils.isBlank(config.getSecretKey())) {
            logFailure(START_AUTHSIGNAL_FLOW, context, null, ExecutorErrorMessages.SECRET_KEY_NOT_CONFIGURED, null);
            throw serverException(ExecutorErrorMessages.SECRET_KEY_NOT_CONFIGURED, null, null);
        }

        String actionCode = resolveActionCode(context, config);
        AuthsignalRequest startRequest = new AuthsignalRequest(actionCode).setRedirectUrl(portalUrl);

        String authsignalUserId = null;
        switch (StringUtils.defaultString(flowType)) {
            case FlowType.REGISTRATION:
                // The user does not exist yet, so use the contact details instead of a user ID.
                if (!setContactDetails(startRequest, getFlowUser(context))) {
                    logFailure(START_AUTHSIGNAL_FLOW, context, actionCode,
                            ExecutorErrorMessages.CONTACT_DETAILS_NOT_FOUND, null);
                    return userErrorResponse(ExecutorErrorMessages.CONTACT_DETAILS_NOT_FOUND, null);
                }
                break;
            case FlowType.INVITED_USER_REGISTRATION:
            case FlowType.PASSWORD_RECOVERY:
                // The user already exists, and the WSO2 user ID is the Authsignal user ID.
                authsignalUserId = localUserId(context);
                if (authsignalUserId == null) {
                    return userErrorResponse(ExecutorErrorMessages.USER_NOT_IDENTIFIED, null);
                }
                startRequest.setUserId(authsignalUserId);
                break;
            default:
                throw unsupportedFlowType(context);
        }

        AuthsignalResponse startResponse;
        try {
            startResponse = createClient(config).startFlow(startRequest);
        } catch (AuthsignalConnectionException e) {
            return handleConnectionFailure(ExecutorErrorMessages.START_FLOW_FAILED, authsignalUserId, e,
                    START_AUTHSIGNAL_FLOW, context, actionCode);
        }
        AuthsignalDiagnosticLogUtil.triggerSuccessLog(START_AUTHSIGNAL_FLOW, Messages.FLOW_STARTED,
                () -> logInputs(context, actionCode));
        if (StringUtils.isBlank(startResponse.getChallengeUrl())) {
            logFailure(START_AUTHSIGNAL_FLOW, context, actionCode, ExecutorErrorMessages.INVALID_START_FLOW_RESPONSE,
                    null);
            throw serverException(ExecutorErrorMessages.INVALID_START_FLOW_RESPONSE, authsignalUserId, null);
        }

        ExecutorResponse response = newResponse(STATUS_EXTERNAL_REDIRECTION);
        Map<String, String> additionalInfo = new HashMap<>();
        additionalInfo.put(REDIRECT_URL, startResponse.getChallengeUrl());
        response.setAdditionalInfo(additionalInfo);
        response.setRequiredData(Collections.singletonList(RequestParams.CHALLENGE_TOKEN));
        return response;
    }

    /**
     * Verify the flow result when the user comes back from the pre-built UI.
     */
    private ExecutorResponse processFlowResult(FlowExecutionContext context) throws FlowEngineServerException {

        String flowType = context.getFlowType();
        String localUserId = localUserId(context);

        String challengeToken = context.getUserInputData().get(RequestParams.CHALLENGE_TOKEN);
        if (StringUtils.isBlank(challengeToken)) {
            return userErrorResponse(ExecutorErrorMessages.MISSING_TOKEN, localUserId);
        }

        AuthsignalConfig config;
        try {
            config = resolveConfig(context.getTenantDomain());
        } catch (IdentityGovernanceException e) {
            throw serverException(ExecutorErrorMessages.READING_CONFIG, null, e);
        }
        String actionCode = resolveActionCode(context, config);
        AuthsignalResponse result;
        try {
            result = createClient(config).verifyFlow(actionCode, challengeToken);
        } catch (AuthsignalConnectionException e) {
            return handleConnectionFailure(ExecutorErrorMessages.VERIFY_FLOW_FAILED, localUserId, e,
                    VERIFY_AUTHSIGNAL_FLOW, context, actionCode);
        }
        AuthsignalDiagnosticLogUtil.triggerSuccessLog(VERIFY_AUTHSIGNAL_FLOW, Messages.FLOW_RESULT_RECEIVED,
                () -> AuthsignalDiagnosticLogUtil.addFlowResult(logInputs(context, actionCode), result));
        if (!ActionState.CHALLENGE_SUCCEEDED.equals(result.getState())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal flow is in state: " + result.getState());
            }
            logFailure(VERIFY_AUTHSIGNAL_FLOW, context, actionCode, ExecutorErrorMessages.CHALLENGE_NOT_SUCCEEDED,
                    null);
            return userErrorResponse(ExecutorErrorMessages.CHALLENGE_NOT_SUCCEEDED, localUserId);
        }

        ExecutorResponse errorResponse;
        switch (StringUtils.defaultString(flowType)) {
            case FlowType.REGISTRATION:
                errorResponse = processRegistrationResult(context, result, actionCode);
                break;
            case FlowType.INVITED_USER_REGISTRATION:
            case FlowType.PASSWORD_RECOVERY:
                errorResponse = processExistingUserResult(context, result, actionCode);
                break;
            default:
                throw unsupportedFlowType(context);
        }
        if (errorResponse != null) {
            return errorResponse;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal flow: " + actionCode + " succeeded in flow type: " + flowType);
        }
        AuthsignalDiagnosticLogUtil.triggerSuccessLog(VERIFY_AUTHSIGNAL_FLOW, Messages.VERIFICATION_COMPLETED,
                () -> logInputs(context, actionCode));
        return newResponse(STATUS_COMPLETE);
    }

    /**
     * Check the result of a registration flow. The user has no Authsignal user ID yet, so the email address or phone
     * number is matched instead. The challenge ID of the verified flow is kept, so that the flow listener can link
     * the Authsignal user to the WSO2 user once the user is created. The verified contact details and the passkey
     * status are saved once the listener links the user.
     *
     * @return An error response, or null if the result is accepted.
     */
    private static ExecutorResponse processRegistrationResult(FlowExecutionContext context, AuthsignalResponse result,
                                                              String actionCode) throws FlowEngineServerException {

        if (!isVerifiedIdentifier(getIdentifier(getFlowUser(context)), result.getVerifiedEmail(),
                result.getVerifiedPhoneNumber())) {
            logFailure(VERIFY_AUTHSIGNAL_FLOW, context, actionCode, ExecutorErrorMessages.CONTACT_DETAILS_MISMATCH,
                    null);
            return userErrorResponse(ExecutorErrorMessages.CONTACT_DETAILS_MISMATCH, null);
        }
        if (StringUtils.isBlank(result.getChallengeId())) {
            logFailure(VERIFY_AUTHSIGNAL_FLOW, context, actionCode, ExecutorErrorMessages.INVALID_VERIFY_FLOW_RESPONSE,
                    null);
            throw serverException(ExecutorErrorMessages.INVALID_VERIFY_FLOW_RESPONSE, null, null);
        }
        context.setProperty(FlowContextProps.CHALLENGE_ID, result.getChallengeId());
        return null;
    }

    /**
     * Check the result of a flow of an existing user, who is already linked to Authsignal by the user ID, and save
     * the passkey status.
     *
     * @return An error response, or null if the result is accepted.
     */
    private static ExecutorResponse processExistingUserResult(FlowExecutionContext context,
                                                              AuthsignalResponse result, String actionCode) {

        String localUserId = localUserId(context);
        String verifiedUserId = result.getUser() != null ? result.getUser().getUserId() : null;
        if (localUserId == null || !StringUtils.equals(localUserId, verifiedUserId)) {
            logFailure(VERIFY_AUTHSIGNAL_FLOW, context, actionCode, ExecutorErrorMessages.USER_MISMATCH, null);
            return userErrorResponse(ExecutorErrorMessages.USER_MISMATCH, localUserId);
        }
        FlowUser flowUser = getFlowUser(context);
        String username = StringUtils.trimToNull(flowUser.getUsername());
        if (username != null) {
            AuthsignalUtil.savePasskeyManagedExternallyClaim(context.getTenantDomain(),
                    IdentityUtil.addDomainToName(UserCoreUtil.removeDomainFromName(username),
                            flowUser.getUserStoreDomain()), result.hasPasskey());
        }
        return null;
    }

    /**
     * Get the action code set in the executor metadata of the node, or the one in the connector configuration.
     */
    private static String resolveActionCode(FlowExecutionContext context, AuthsignalConfig config) {

        NodeConfig node = context.getCurrentNode();
        ExecutorDTO executorConfig = node != null ? node.getExecutorConfig() : null;
        Map<String, String> metadata = executorConfig != null ? executorConfig.getMetadata() : null;
        String actionCode =
                metadata != null ? StringUtils.trimToNull(metadata.get(ExecutorMetadata.ACTION_CODE)) : null;
        return actionCode != null ? actionCode : config.getActionCode();
    }

    protected AuthsignalConfig resolveConfig(String tenantDomain) throws IdentityGovernanceException {

        return AuthsignalUtil.getConfig(tenantDomain);
    }

    protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalConnectionException {

        return new AuthsignalClient(config);
    }

    /**
     * Check that the user verified the email address or phone number the flow was started with in this flow.
     */
    private static boolean isVerifiedIdentifier(String identifier, String verifiedEmail, String verifiedMobile) {

        if (identifier == null) {
            return false;
        }
        return identifier.equalsIgnoreCase(verifiedEmail) || identifier.equals(verifiedMobile);
    }

    /**
     * Identify the new user by the email address, or else the E.164 mobile number. Authsignal takes one user
     * identifier only, so the mobile number is passed as a hint when there is an email address.
     *
     * @return false if the user has neither.
     */
    private static boolean setContactDetails(AuthsignalRequest request, FlowUser flowUser) {

        String email = getClaim(flowUser, AuthsignalConstants.EMAIL_CLAIM);
        String mobile = getE164Mobile(flowUser);
        if (email != null) {
            request.setUserEmail(email).setHintPhoneNumber(mobile);
            return true;
        }
        if (mobile != null) {
            request.setUserPhoneNumber(mobile);
            return true;
        }
        return false;
    }

    /**
     * Get the email address, or else the E.164 mobile number, that the registration flow is started with.
     */
    private static String getIdentifier(FlowUser flowUser) {

        String email = getClaim(flowUser, AuthsignalConstants.EMAIL_CLAIM);
        return email != null ? email : getE164Mobile(flowUser);
    }

    /**
     * Get the user's mobile number if it is in E.164 format.
     */
    private static String getE164Mobile(FlowUser flowUser) {

        String mobile = getClaim(flowUser, AuthsignalConstants.MOBILE_CLAIM);
        return mobile != null && mobile.startsWith("+") ? mobile : null;
    }

    private static String getClaim(FlowUser flowUser, String claimUri) {

        Object value = flowUser.getClaim(claimUri);
        return value != null ? StringUtils.trimToNull(String.valueOf(value)) : null;
    }

    /**
     * Get the WSO2 user ID of the user the flow is for, which is also the user's Authsignal user ID. It does not
     * contain any personal data, so it can be added to error descriptions.
     *
     * @return The ID, or null if the user is not known.
     */
    private static String localUserId(FlowExecutionContext context) {

        return StringUtils.trimToNull(getFlowUser(context).getUserId());
    }

    /**
     * Check whether the user came back from the pre-built UI with a challenge token.
     */
    private static boolean isFlowCallback(FlowExecutionContext context) {

        Map<String, String> inputs = context.getUserInputData();
        return inputs != null && inputs.containsKey(RequestParams.CHALLENGE_TOKEN);
    }

    private static FlowUser getFlowUser(FlowExecutionContext context) {

        return context.getFlowUser() != null ? context.getFlowUser() : new FlowUser();
    }

    /**
     * Get the inputs of a flow diagnostic log: the flow type, the application, the action code and the user ID.
     */
    private static Map<String, Object> logInputs(FlowExecutionContext context, String actionCode) {

        Map<String, Object> inputs = AuthsignalDiagnosticLogUtil.commonInputs(actionCode, localUserId(context));
        AuthsignalDiagnosticLogUtil.putIfNotNull(inputs, InputKeys.FLOW_TYPE, context.getFlowType());
        AuthsignalDiagnosticLogUtil.putIfNotNull(inputs, LogConstants.InputKeys.APPLICATION_ID,
                StringUtils.trimToNull(context.getApplicationId()));
        return inputs;
    }

    /**
     * Trigger the diagnostic log of a failure, with the HTTP status if an Authsignal call failed.
     */
    private static void logFailure(String actionId, FlowExecutionContext context, String actionCode,
                                   ExecutorErrorMessages error, Throwable cause) {

        AuthsignalDiagnosticLogUtil.triggerFailureLog(actionId, error.getMessage(), cause,
                () -> logInputs(context, actionCode));
    }

    private static FlowEngineServerException unsupportedFlowType(FlowExecutionContext context) {

        String message = String.format(ExecutorErrorMessages.UNSUPPORTED_FLOW_TYPE.getMessage(),
                context.getFlowType());
        return serverException(message, null);
    }

    /**
     * Check whether Authsignal rejected the request, such as for an invalid or expired challenge token, rather than
     * failing to process it.
     */
    private static boolean isRejected(AuthsignalConnectionException e) {

        return e.isClientError() && !e.isTransient();
    }

    private static ExecutorResponse newResponse(String status) {

        // Only the no-argument constructor sets up the error details.
        ExecutorResponse response = new ExecutorResponse();
        response.setResult(status);
        return response;
    }

    /**
     * Build a response for an error the user can act on, without an error code, so that the flow engine reports it
     * under its generic executor error code with the message as the error description.
     */
    private static ExecutorResponse userErrorResponse(ExecutorErrorMessages error, String userId) {

        ExecutorResponse response = newResponse(STATUS_USER_ERROR);
        response.setErrorMessage(describe(error.getMessage(), userId));
        return response;
    }

    /**
     * Log a failed Authsignal call and report it as a user error if Authsignal rejected the request, or else as a
     * server error.
     */
    private static ExecutorResponse handleConnectionFailure(ExecutorErrorMessages error, String userId,
                                                            AuthsignalConnectionException e, String actionId,
                                                            FlowExecutionContext context, String actionCode)
            throws FlowEngineServerException {

        logFailure(actionId, context, actionCode, error, e);
        if (isRejected(e)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal rejected the request with HTTP " + e.getStatusCode() + ".", e);
            }
            return userErrorResponse(error, userId);
        }
        throw serverException(error, userId, e);
    }

    /**
     * Build an exception for an error the user cannot do anything about, such as a misconfiguration or a failed call
     * to Authsignal.
     */
    private static FlowEngineServerException serverException(ExecutorErrorMessages error, String userId,
                                                             Throwable cause) {

        return serverException(describe(error.getMessage(), userId), cause);
    }

    private static FlowEngineServerException serverException(String description, Throwable cause) {

        return new FlowEngineServerException(ERROR_CODE_EXECUTOR_FAILURE.getCode(),
                ERROR_CODE_EXECUTOR_FAILURE.getMessage(), description, cause);
    }

    private static String describe(String message, String userId) {

        return userId != null ? String.format(USER_ID_DESCRIPTION, message, userId) : message;
    }

    /**
     * Load the executor icon bundled with the connector as a data URL, so the Console can show it without hosting it.
     */
    private static String loadIcon() {

        try (InputStream icon = AuthsignalExecutor.class.getClassLoader()
                .getResourceAsStream(AuthsignalConstants.EXECUTOR_ICON_PATH)) {
            if (icon == null) {
                LOG.warn("Authsignal executor icon not found: " + AuthsignalConstants.EXECUTOR_ICON_PATH);
                return null;
            }
            return "data:image/svg+xml;base64," + Base64.getEncoder().encodeToString(icon.readAllBytes());
        } catch (IOException e) {
            LOG.warn("Error while loading the Authsignal executor icon.", e);
            return null;
        }
    }
}
