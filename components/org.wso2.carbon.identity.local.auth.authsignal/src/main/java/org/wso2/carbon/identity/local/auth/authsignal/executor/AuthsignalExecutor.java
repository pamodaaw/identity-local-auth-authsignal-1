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
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
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
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ActionStepType;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ExecutorErrorMessages;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ExecutorMetadata;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowContextProps;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowType;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.RequestParams;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalConnectionException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalRequest;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalResponse;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;

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
import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.AUTHSIGNAL_SERVICE;
import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.ActionIDs.PROCESS_AUTHSIGNAL_FLOW_RESULT;
import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.ActionIDs.START_AUTHSIGNAL_FLOW;

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

        // TODO: Add support for secured self-service operations once the flow type is available in the flow engine.
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
            throw serverException(ExecutorErrorMessages.SECRET_KEY_NOT_CONFIGURED, null, null);
        }

        String actionCode = resolveActionCode(context, config);
        AuthsignalRequest startRequest = new AuthsignalRequest(actionCode).setRedirectUrl(portalUrl);

        String authsignalUserId = null;
        switch (StringUtils.defaultString(flowType)) {
            case FlowType.REGISTRATION:
                // The user does not exist yet, so use the contact details instead of a user ID.
                if (!setContactDetails(startRequest, getFlowUser(context))) {
                    triggerDiagnosticLog(START_AUTHSIGNAL_FLOW,
                            ExecutorErrorMessages.CONTACT_DETAILS_NOT_FOUND.getMessage(),
                            DiagnosticLog.ResultStatus.FAILED, context, actionCode);
                    return userErrorResponse(ExecutorErrorMessages.CONTACT_DETAILS_NOT_FOUND, null);
                }
                break;
            case FlowType.INVITED_USER_REGISTRATION:
            case FlowType.PASSWORD_RECOVERY:
            case FlowType.SECURED_SELF_SERVICE_OPERATIONS:
                // The user already exists, and the WSO2 user ID is the Authsignal user ID.
                authsignalUserId = localUserId(context);
                if (authsignalUserId == null) {
                    triggerDiagnosticLog(START_AUTHSIGNAL_FLOW, ExecutorErrorMessages.USER_NOT_IDENTIFIED.getMessage(),
                            DiagnosticLog.ResultStatus.FAILED, context, actionCode);
                    return userErrorResponse(ExecutorErrorMessages.USER_NOT_IDENTIFIED, null);
                }
                startRequest.setUserId(authsignalUserId);
                break;
            default:
                throw unsupportedFlowType(flowType);
        }

        AuthsignalResponse startResponse;
        try {
            startResponse = createClient(config).startFlow(startRequest);
        } catch (AuthsignalConnectionException e) {
            return handleConnectionFailure(ExecutorErrorMessages.START_FLOW_FAILED, authsignalUserId, e,
                    START_AUTHSIGNAL_FLOW, context, actionCode);
        }
        if (StringUtils.isBlank(startResponse.getChallengeUrl())
                || (FlowType.REGISTRATION.equals(flowType) && StringUtils.isBlank(startResponse.getChallengeId()))) {
            throw serverException(ExecutorErrorMessages.INVALID_START_FLOW_RESPONSE, authsignalUserId, null);
        }

        ExecutorResponse response = newResponse(STATUS_EXTERNAL_REDIRECTION);
        if (FlowType.REGISTRATION.equals(flowType)) {
            // Used by the flow listener to link the Authsignal user to the WSO2 user once the user is created.
            Map<String, Object> contextProperties = new HashMap<>();
            contextProperties.put(FlowContextProps.CHALLENGE_ID, startResponse.getChallengeId());
            response.setContextProperty(contextProperties);
        }
        Map<String, String> additionalInfo = new HashMap<>();
        additionalInfo.put(REDIRECT_URL, startResponse.getChallengeUrl());
        response.setAdditionalInfo(additionalInfo);
        response.setRequiredData(Collections.singletonList(RequestParams.CHALLENGE_TOKEN));
        triggerDiagnosticLog(START_AUTHSIGNAL_FLOW, "Redirecting the user to the Authsignal pre-built UI.",
                DiagnosticLog.ResultStatus.SUCCESS, context, actionCode);
        return response;
    }

    /**
     * Verify the flow result when the user comes back from the pre-built UI.
     */
    private ExecutorResponse processFlowResult(FlowExecutionContext context) throws FlowEngineServerException {

        String flowType = context.getFlowType();
        String localUserId = localUserId(context);
        // The challenge ID is kept only for a successful registration flow.
        Object challengeId = removeProperty(context, FlowContextProps.CHALLENGE_ID);

        String challengeToken = context.getUserInputData().get(RequestParams.CHALLENGE_TOKEN);
        if (StringUtils.isBlank(challengeToken)) {
            triggerDiagnosticLog(PROCESS_AUTHSIGNAL_FLOW_RESULT, ExecutorErrorMessages.MISSING_TOKEN.getMessage(),
                    DiagnosticLog.ResultStatus.FAILED, context, null);
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
                    PROCESS_AUTHSIGNAL_FLOW_RESULT, context, actionCode);
        }

        if (!ActionState.CHALLENGE_SUCCEEDED.equals(result.getState())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal flow is in state: " + result.getState());
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(buildDiagnosticLog(PROCESS_AUTHSIGNAL_FLOW_RESULT,
                        ExecutorErrorMessages.CHALLENGE_NOT_SUCCEEDED.getMessage(), DiagnosticLog.ResultStatus.FAILED,
                        context, actionCode)
                        .inputParam(AuthsignalConstants.LogConstants.InputKeys.FLOW_STATE, result.getState()));
            }
            return userErrorResponse(ExecutorErrorMessages.CHALLENGE_NOT_SUCCEEDED, localUserId);
        }

        ExecutorResponse errorResponse;
        switch (StringUtils.defaultString(flowType)) {
            case FlowType.REGISTRATION:
                errorResponse = processRegistrationResult(context, result, challengeId);
                break;
            case FlowType.INVITED_USER_REGISTRATION:
                // The invited user sets up their authenticators in this flow.
                errorResponse = processExistingUserResult(context, config, result, false);
                break;
            case FlowType.PASSWORD_RECOVERY:
            case FlowType.SECURED_SELF_SERVICE_OPERATIONS:
                errorResponse = processExistingUserResult(context, config, result, true);
                break;
            default:
                throw unsupportedFlowType(flowType);
        }
        if (errorResponse != null) {
            triggerDiagnosticLog(PROCESS_AUTHSIGNAL_FLOW_RESULT, errorResponse.getErrorMessage(),
                    DiagnosticLog.ResultStatus.FAILED, context, actionCode);
            return errorResponse;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal flow: " + actionCode + " succeeded in flow type: " + flowType);
        }
        triggerDiagnosticLog(PROCESS_AUTHSIGNAL_FLOW_RESULT, "Authsignal flow completed successfully.",
                DiagnosticLog.ResultStatus.SUCCESS, context, actionCode);
        return newResponse(STATUS_COMPLETE);
    }

    /**
     * Check the result of a registration flow. The user has no Authsignal user ID yet, so the email address or phone
     * number is matched instead. The verified contact details and the passkey status are saved once the listener
     * links the user.
     *
     * @return An error response, or null if the result is accepted.
     */
    private static ExecutorResponse processRegistrationResult(FlowExecutionContext context, AuthsignalResponse result,
                                                              Object challengeId) {

        if (!isVerifiedIdentifier(getIdentifier(getFlowUser(context)), result.getVerifiedEmail(),
                result.getVerifiedPhoneNumber())
                || !(challengeId instanceof String) || StringUtils.isBlank((String) challengeId)) {
            return userErrorResponse(ExecutorErrorMessages.CONTACT_DETAILS_MISMATCH, null);
        }
        context.setProperty(FlowContextProps.CHALLENGE_ID, challengeId);
        return null;
    }

    /**
     * Check the result of a flow of an existing user, who is already linked to Authsignal by the user ID, and save
     * the passkey status.
     *
     * @param requireEnrolled Whether to accept only authenticators the user already had, not newly enrolled ones.
     * @return An error response, or null if the result is accepted.
     */
    private static ExecutorResponse processExistingUserResult(FlowExecutionContext context, AuthsignalConfig config,
                                                              AuthsignalResponse result, boolean requireEnrolled) {

        String localUserId = localUserId(context);
        String verifiedUserId = result.getUser() != null ? result.getUser().getUserId() : null;
        if (localUserId == null || !StringUtils.equals(localUserId, verifiedUserId)) {
            return userErrorResponse(ExecutorErrorMessages.USER_MISMATCH, localUserId);
        }
        if (requireEnrolled && !isVerifiedWithEnrolledAuthenticators(result)) {
            return userErrorResponse(ExecutorErrorMessages.USER_NOT_ENROLLED, localUserId);
        }
        FlowUser flowUser = getFlowUser(context);
        String username = StringUtils.trimToNull(flowUser.getUsername());
        if (username != null) {
            AuthsignalUtil.savePasskeyEnrolledClaim(config, context.getTenantDomain(),
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
     * Check that every completed step used an authenticator the user already had.
     */
    private static boolean isVerifiedWithEnrolledAuthenticators(AuthsignalResponse result) {

        List<AuthsignalResponse.Step> steps = result.getAction().getCompletedSteps();
        if (steps.isEmpty()) {
            return false;
        }
        for (AuthsignalResponse.Step step : steps) {
            if (!ActionStepType.VERIFICATION_REQUIRED.equals(step.getStepType())) {
                return false;
            }
        }
        return true;
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

    private static void triggerDiagnosticLog(String actionId, String message, DiagnosticLog.ResultStatus status,
                                             FlowExecutionContext context, String actionCode) {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(buildDiagnosticLog(actionId, message, status, context, actionCode));
        }
    }

    /**
     * Build a diagnostic log of the flow. Only the user ID is added to identify the user, as the other user details
     * are personal data.
     */
    private static DiagnosticLog.DiagnosticLogBuilder buildDiagnosticLog(String actionId, String message,
                                                                         DiagnosticLog.ResultStatus status,
                                                                         FlowExecutionContext context,
                                                                         String actionCode) {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                new DiagnosticLog.DiagnosticLogBuilder(AUTHSIGNAL_SERVICE, actionId);
        diagnosticLogBuilder.resultMessage(message)
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(status)
                .inputParam(AuthsignalConstants.LogConstants.InputKeys.FLOW_TYPE, context.getFlowType());
        if (actionCode != null) {
            diagnosticLogBuilder.inputParam(AuthsignalConstants.LogConstants.InputKeys.ACTION_CODE, actionCode);
        }
        String userId = localUserId(context);
        if (userId != null) {
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID, userId);
        }
        return diagnosticLogBuilder;
    }

    private static FlowEngineServerException unsupportedFlowType(String flowType) {

        return serverException(String.format(ExecutorErrorMessages.UNSUPPORTED_FLOW_TYPE.getMessage(), flowType),
                null);
    }

    /**
     * Check whether Authsignal rejected the request, such as for an invalid or expired challenge token, rather than
     * failing to process it.
     */
    private static boolean isRejected(AuthsignalConnectionException e) {

        return e.isClientError() && !e.isTransient();
    }

    private static Object removeProperty(FlowExecutionContext context, String property) {

        return context.getProperties() != null ? context.getProperties().remove(property) : null;
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
     * Report a failed Authsignal call as a user error if Authsignal rejected the request, or else as a server error.
     */
    private static ExecutorResponse handleConnectionFailure(ExecutorErrorMessages error, String userId,
                                                            AuthsignalConnectionException e, String actionId,
                                                            FlowExecutionContext context, String actionCode)
            throws FlowEngineServerException {

        triggerDiagnosticLog(actionId, error.getMessage(), DiagnosticLog.ResultStatus.FAILED, context, actionCode);
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
