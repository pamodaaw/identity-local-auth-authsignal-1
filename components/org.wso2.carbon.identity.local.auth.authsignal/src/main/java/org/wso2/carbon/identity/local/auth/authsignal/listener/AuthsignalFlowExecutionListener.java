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
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.listener.AbstractFlowExecutionListener;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowContextProps;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.FlowType;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.InputKeys;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.Messages;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalConnectionException;
import org.wso2.carbon.identity.local.auth.authsignal.executor.AuthsignalExecutor;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalDiagnosticLogUtil;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.STATUS_COMPLETE;
import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.ActionIDs.LINK_AUTHSIGNAL_USER;

/**
 * Links the Authsignal user that {@link AuthsignalExecutor} started registration with to the new WSO2 user. Once the
 * link succeeds, the contact details verified on Authsignal are marked as verified and the passkey status is saved. If
 * Authsignal cannot be reached, the challenge ID is saved on the user so that the link is completed at the next
 * sign-in.
 */
public class AuthsignalFlowExecutionListener extends AbstractFlowExecutionListener {

    private static final Log LOG = LogFactory.getLog(AuthsignalFlowExecutionListener.class);

    private static final int DEFAULT_ORDER_ID = 50;

    @Override
    public int getDefaultOrderId() {

        return DEFAULT_ORDER_ID;
    }

    @Override
    public int getExecutionOrderId() {

        return DEFAULT_ORDER_ID;
    }

    @Override
    public boolean isEnabled() {

        return true;
    }

    @Override
    public boolean doPostExecute(FlowExecutionStep step, FlowExecutionContext context) {

        if (step == null || !STATUS_COMPLETE.equals(step.getFlowStatus())
                || !FlowType.REGISTRATION.equals(context.getFlowType())) {
            return true;
        }
        Object challengeId = context.getProperty(FlowContextProps.CHALLENGE_ID);
        if (!(challengeId instanceof String) || StringUtils.isBlank((String) challengeId)) {
            return true;
        }
        // Identify user only works once per flow.
        context.getProperties().remove(FlowContextProps.CHALLENGE_ID);
        identifyUser(context, (String) challengeId);
        return true;
    }

    private void identifyUser(FlowExecutionContext context, String challengeId) {

        String tenantDomain = context.getTenantDomain();
        FlowUser flowUser = context.getFlowUser();
        if (flowUser == null || StringUtils.isBlank(flowUser.getUserId())) {
            // For example, the registration is pending approval and the user is not created yet.
            LOG.warn("The user registered with Authsignal is not created in the tenant: " + tenantDomain
                    + ". The Authsignal user is not linked to a WSO2 user.");
            AuthsignalDiagnosticLogUtil.triggerFailureLog(LINK_AUTHSIGNAL_USER, Messages.USER_NOT_CREATED, null,
                    () -> logInputs(context, null));
            return;
        }
        String username = IdentityUtil.addDomainToName(getUsername(flowUser), flowUser.getUserStoreDomain());
        try {
            AuthsignalConfig config = resolveConfig(tenantDomain);
            Map<String, String> claims;
            try {
                // Saved only once the user is linked, from the authenticators the user verified on Authsignal.
                claims = AuthsignalUtil.syncUserIdToAuthsignal(createClient(config), flowUser.getUserId(),
                        challengeId, getClaim(flowUser, AuthsignalConstants.EMAIL_CLAIM),
                        getClaim(flowUser, AuthsignalConstants.MOBILE_CLAIM));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Linked the Authsignal user registered in the flow: "
                            + context.getContextIdentifier() + " to the WSO2 user.");
                }
                Map<String, String> linkedClaims = claims;
                AuthsignalDiagnosticLogUtil.triggerSuccessLog(LINK_AUTHSIGNAL_USER, Messages.USER_LINKED,
                        () -> AuthsignalDiagnosticLogUtil.addUpdatedClaims(
                                logInputs(context, flowUser.getUserId()), linkedClaims));
            } catch (AuthsignalConnectionException e) {
                if (!e.isTransient()) {
                    // For example, the challenge has expired or Authsignal is not configured, so do not retry it.
                    LOG.error("Failed to link the Authsignal user registered in the flow: "
                            + context.getContextIdentifier() + " to the WSO2 user in the tenant: " + tenantDomain
                            + ". The link is not retried.", e);
                    AuthsignalDiagnosticLogUtil.triggerFailureLog(LINK_AUTHSIGNAL_USER,
                            Messages.LINK_FAILED_NOT_RETRIED, e, () -> logInputs(context, flowUser.getUserId()));
                    return;
                }
                // Finished at the user's next sign-in.
                claims = new HashMap<>();
                claims.put(AuthsignalConstants.CHALLENGE_ID_CLAIM, challengeId);
                LOG.warn("Failed to link the Authsignal user registered in the flow: "
                        + context.getContextIdentifier() + " in the tenant: " + tenantDomain
                        + ". The link will be completed at the user's next sign-in.");
                AuthsignalDiagnosticLogUtil.triggerFailureLog(LINK_AUTHSIGNAL_USER, Messages.LINK_FAILED_RETRIED, e,
                        () -> logInputs(context, flowUser.getUserId()));
            }
            if (!claims.isEmpty()) {
                AuthsignalUtil.setUserClaims(tenantDomain, username, claims);
            }
        } catch (IdentityGovernanceException | UserStoreException | RuntimeException e) {
            LOG.error("Failed to save the Authsignal registration of the flow: " + context.getContextIdentifier()
                    + " on the WSO2 user in the tenant: " + tenantDomain + ".", e);
            AuthsignalDiagnosticLogUtil.triggerFailureLog(LINK_AUTHSIGNAL_USER, Messages.SAVING_LINK_FAILED, e,
                    () -> logInputs(context, flowUser.getUserId()));
        }
    }

    protected AuthsignalConfig resolveConfig(String tenantDomain) throws IdentityGovernanceException {

        return AuthsignalUtil.getConfig(tenantDomain);
    }

    protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalConnectionException {

        return new AuthsignalClient(config);
    }

    /**
     * Get the inputs of a diagnostic log of the registration: the flow type, the application and the user ID.
     */
    private static Map<String, Object> logInputs(FlowExecutionContext context, String userId) {

        Map<String, Object> inputs = AuthsignalDiagnosticLogUtil.commonInputs(null, userId);
        AuthsignalDiagnosticLogUtil.putIfNotNull(inputs, InputKeys.FLOW_TYPE, context.getFlowType());
        AuthsignalDiagnosticLogUtil.putIfNotNull(inputs, LogConstants.InputKeys.APPLICATION_ID,
                StringUtils.trimToNull(context.getApplicationId()));
        return inputs;
    }

    private static String getUsername(FlowUser flowUser) {

        return UserCoreUtil.removeDomainFromName(flowUser.getUsername());
    }

    private static String getClaim(FlowUser flowUser, String claimUri) {

        Object value = flowUser.getClaim(claimUri);
        return value != null ? StringUtils.trimToNull(String.valueOf(value)) : null;
    }
}
