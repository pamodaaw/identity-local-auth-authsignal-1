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

package org.wso2.carbon.identity.local.auth.authsignal.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.listener.FlowExecutionListener;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.AuthsignalAuthenticator;
import org.wso2.carbon.identity.local.auth.authsignal.connector.AuthsignalConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.executor.AuthsignalExecutor;
import org.wso2.carbon.identity.local.auth.authsignal.listener.AuthsignalFlowExecutionListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi service component of the Authsignal connector.
 */
@Component(
        name = "identity.local.auth.authsignal.component",
        immediate = true
)
public class AuthsignalConnectorServiceComponent {

    private static final Log LOG = LogFactory.getLog(AuthsignalConnectorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(IdentityConnectorConfig.class.getName(),
                    new AuthsignalConnectorConfig(), null);
            bundleContext.registerService(ApplicationAuthenticator.class.getName(),
                    new AuthsignalAuthenticator(), null);
            bundleContext.registerService(Executor.class.getName(), new AuthsignalExecutor(), null);

            // Links the Authsignal user to the WSO2 user after registration.
            bundleContext.registerService(FlowExecutionListener.class.getName(),
                    new AuthsignalFlowExecutionListener(), null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authsignal connector is activated.");
            }
        } catch (Throwable e) {
            LOG.error("Error while activating the Authsignal connector.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authsignal connector is deactivated.");
        }
    }

    @Reference(
            name = "RealmService",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        AuthsignalConnectorDataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        AuthsignalConnectorDataHolder.setRealmService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        AuthsignalConnectorDataHolder.setIdentityGovernanceService(identityGovernanceService);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        AuthsignalConnectorDataHolder.setIdentityGovernanceService(null);
    }
}
