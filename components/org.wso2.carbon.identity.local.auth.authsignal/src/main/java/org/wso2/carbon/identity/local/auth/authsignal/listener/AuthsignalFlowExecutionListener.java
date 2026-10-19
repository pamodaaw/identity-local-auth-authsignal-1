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
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.listener.AbstractFlowExecutionListener;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.authsignal.client.AuthsignalClient;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalClientException;
import org.wso2.carbon.identity.local.auth.authsignal.executor.AuthsignalExecutor;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalConfig;
import org.wso2.carbon.identity.local.auth.authsignal.model.FlowResponse;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalConfigResolver;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUserIdResolver;
import org.wso2.carbon.identity.local.auth.authsignal.util.AuthsignalUserStoreUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.STATUS_COMPLETE;

/**
 * Completes an Authsignal sign-up once the registration flow has created the WSO2 user.
 * <p>
 * {@link AuthsignalExecutor} starts the Authsignal flow before the WSO2 user exists, so Authsignal holds what the user
 * enrolled under a temporary user ID. When the registration flow completes, this listener calls Identify User with
 * the new user's Authsignal user ID and the challenge ID kept in the flow context, which moves everything enrolled in
 * the flow to that ID. It then saves the email address and phone number Authsignal verified on the WSO2 user.
 * <p>
 * The WSO2 user is already created when this runs, so failures are logged and never fail the flow.
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
                || !AuthsignalExecutor.REGISTRATION.equals(context.getFlowType())) {
            return true;
        }
        Object challengeId = context.getProperty(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID);
        if (!(challengeId instanceof String) || StringUtils.isBlank((String) challengeId)) {
            return true;
        }
        // Identify User only works once per flow.
        context.getProperties().remove(AuthsignalExecutor.CONTEXT_PROP_CHALLENGE_ID);
        boolean passkeyEnrolled = Boolean.TRUE.equals(
                context.getProperties().remove(AuthsignalExecutor.CONTEXT_PROP_PASSKEY_ENROLLED));
        identifyUser(context, (String) challengeId, passkeyEnrolled);
        return true;
    }

    private void identifyUser(FlowExecutionContext context, String challengeId, boolean passkeyEnrolled) {

        String tenantDomain = context.getTenantDomain();
        FlowUser flowUser = context.getFlowUser();
        if (flowUser == null || StringUtils.isBlank(flowUser.getUserId())) {
            // For example, the registration is pending approval and the user is not created yet.
            LOG.warn("The user registered with Authsignal is not created in the tenant: " + tenantDomain
                    + ". The Authsignal user is not linked to a WSO2 user.");
            return;
        }
        try {
            AuthsignalConfig config = resolveConfig(tenantDomain);
            String authsignalUserId = resolveAuthsignalUserId(tenantDomain, flowUser, config);
            FlowResponse response = createClient(config).identifyUser(authsignalUserId, challengeId);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Linked the Authsignal user registered in the flow: " + context.getContextIdentifier()
                        + " to the WSO2 user.");
            }
            saveUserClaims(tenantDomain, flowUser, response.getUser(), config,
                    passkeyEnrolled || response.hasPasskey());
        } catch (AuthsignalClientException | IdentityGovernanceException | UserStoreException
                 | RuntimeException e) {
            LOG.error("Failed to link the Authsignal user registered in the flow: " + context.getContextIdentifier()
                    + " to the WSO2 user in the tenant: " + tenantDomain + ".", e);
        }
    }

    /**
     * Save the email address and phone number Authsignal verified during the flow on the WSO2 user, marked as
     * verified, along with whether the user has a passkey on Authsignal in the passkey enrolled claim, if configured.
     */
    private void saveUserClaims(String tenantDomain, FlowUser flowUser, FlowResponse.User user,
                                AuthsignalConfig config, boolean passkeyEnrolled) throws UserStoreException {

        Map<String, String> claims = new HashMap<>();
        AuthsignalUserStoreUtil.putPasskeyEnrolledClaim(claims, config, passkeyEnrolled);
        if (user != null) {
            String email = user.getVerifiedEmail();
            if (StringUtils.isNotBlank(email)) {
                claims.put(AuthsignalConstants.EMAIL_CLAIM, email);
                claims.put(AuthsignalConstants.EMAIL_VERIFIED_CLAIM, Boolean.TRUE.toString());
            }
            String phoneNumber = user.getVerifiedPhoneNumber();
            if (StringUtils.isNotBlank(phoneNumber)) {
                claims.put(AuthsignalConstants.MOBILE_CLAIM, phoneNumber);
                claims.put(AuthsignalConstants.MOBILE_VERIFIED_CLAIM, Boolean.TRUE.toString());
            }
        }
        if (claims.isEmpty()) {
            return;
        }
        // Authsignal already holds these values, so they are not enrolled again.
        AuthsignalUserOperationEventListener.disableSync();
        try {
            AuthsignalUserStoreUtil.setUserClaims(tenantDomain, IdentityUtil.addDomainToName(getUsername(flowUser),
                    flowUser.getUserStoreDomain()), claims);
        } finally {
            AuthsignalUserOperationEventListener.enableSync();
        }
    }

    protected String resolveAuthsignalUserId(String tenantDomain, FlowUser flowUser, AuthsignalConfig config) {

        return AuthsignalUserIdResolver.toAuthsignalUserId(config, flowUser::getUserId, getUsername(flowUser),
                flowUser.getUserStoreDomain(), tenantDomain);
    }

    protected AuthsignalConfig resolveConfig(String tenantDomain) throws IdentityGovernanceException {

        return AuthsignalConfigResolver.resolve(tenantDomain);
    }

    protected AuthsignalClient createClient(AuthsignalConfig config) throws AuthsignalClientException {

        return AuthsignalClient.forConfig(config);
    }

    private static String getUsername(FlowUser flowUser) {

        return UserCoreUtil.removeDomainFromName(flowUser.getUsername());
    }
}
