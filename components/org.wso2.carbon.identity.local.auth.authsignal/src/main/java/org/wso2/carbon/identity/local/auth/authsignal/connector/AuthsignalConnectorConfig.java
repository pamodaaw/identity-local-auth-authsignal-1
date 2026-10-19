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

package org.wso2.carbon.identity.local.auth.authsignal.connector;

import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.Defaults;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Identity governance connector holding the tenant-wise configuration of the Authsignal authenticator.
 */
public class AuthsignalConnectorConfig implements IdentityConnectorConfig {

    public static final String CONNECTOR_NAME = "authsignal-authenticator";
    public static final String CONNECTOR_FRIENDLY_NAME = "Authsignal";
    public static final String CONNECTOR_CATEGORY = "Multi Factor Authenticators";
    public static final String CONNECTOR_SUB_CATEGORY = "DEFAULT";
    public static final int CONNECTOR_ORDER = 0;

    // The __secret__ prefix renders the field as a password input; the property is also marked confidential so
    // the governance REST API masks it in responses.
    public static final String SECRET_KEY = "__secret__.Authsignal.SecretKey";
    public static final String REGION = "Authsignal.Region";
    public static final String USER_IDENTIFIER = "Authsignal.UserIdentifier";
    // Action codes of the Authsignal flows used in each journey.
    public static final String SIGN_IN_FLOW_REF = "Authsignal.SignInFlowRef";
    public static final String REGISTRATION_FLOW_REF = "Authsignal.RegistrationFlowRef";
    public static final String RECOVERY_FLOW_REF = "Authsignal.RecoveryFlowRef";
    public static final String SYNC_CONTACT_DETAILS = "Authsignal.SyncContactDetails";
    public static final String DELETE_USERS = "Authsignal.DeleteUsers";
    // URI of the local claim recording whether the user has a passkey on Authsignal. Not updated when empty.
    public static final String PASSKEY_ENROLLED_CLAIM = "Authsignal.PasskeyEnrolledClaim";

    public static final String[] PROPERTY_NAMES = {SECRET_KEY, REGION, USER_IDENTIFIER, SIGN_IN_FLOW_REF,
            REGISTRATION_FLOW_REF, RECOVERY_FLOW_REF, SYNC_CONTACT_DETAILS, DELETE_USERS, PASSKEY_ENROLLED_CLAIM};

    @Override
    public String getName() {

        return CONNECTOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return CONNECTOR_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {

        return CONNECTOR_CATEGORY;
    }

    @Override
    public String getSubCategory() {

        return CONNECTOR_SUB_CATEGORY;
    }

    @Override
    public int getOrder() {

        return CONNECTOR_ORDER;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(SECRET_KEY, "Secret key");
        nameMapping.put(REGION, "Region");
        nameMapping.put(USER_IDENTIFIER, "User identifier");
        nameMapping.put(SIGN_IN_FLOW_REF, "Sign-in flow");
        nameMapping.put(REGISTRATION_FLOW_REF, "Registration flow");
        nameMapping.put(RECOVERY_FLOW_REF, "Password recovery flow");
        nameMapping.put(SYNC_CONTACT_DETAILS, "Sync contact detail changes");
        nameMapping.put(DELETE_USERS, "Delete users on Authsignal");
        nameMapping.put(PASSKEY_ENROLLED_CLAIM, "Passkey enrolled claim");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(SECRET_KEY,
                "Server API secret key of the Authsignal tenant");
        descriptionMapping.put(REGION,
                "Region of the Authsignal tenant: us, eu, au, ca or uk");
        descriptionMapping.put(USER_IDENTIFIER,
                "Value used as the Authsignal user ID: userId (WSO2 user UUID) or username");
        descriptionMapping.put(SIGN_IN_FLOW_REF,
                "Action code of the Authsignal flow used at sign-in");
        descriptionMapping.put(REGISTRATION_FLOW_REF,
                "Action code of the Authsignal flow used in registration flows");
        descriptionMapping.put(RECOVERY_FLOW_REF,
                "Action code of the Authsignal flow used in password recovery flows");
        descriptionMapping.put(SYNC_CONTACT_DETAILS,
                "Update the user's verified email address and mobile number on Authsignal when they change");
        descriptionMapping.put(DELETE_USERS,
                "Delete the user and their authenticators on Authsignal when the user is deleted");
        descriptionMapping.put(PASSKEY_ENROLLED_CLAIM,
                "URI of the local claim set to true or false based on whether the user has a passkey on Authsignal."
                        + " Leave empty to not update any claim");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        return PROPERTY_NAMES.clone();
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        Properties properties = new Properties();
        properties.put(SECRET_KEY, "");
        properties.put(REGION, Defaults.REGION);
        properties.put(USER_IDENTIFIER, Defaults.USER_IDENTIFIER);
        properties.put(SIGN_IN_FLOW_REF, Defaults.SIGN_IN_FLOW_REF);
        properties.put(REGISTRATION_FLOW_REF, Defaults.REGISTRATION_FLOW_REF);
        properties.put(RECOVERY_FLOW_REF, Defaults.RECOVERY_FLOW_REF);
        properties.put(SYNC_CONTACT_DETAILS, String.valueOf(Defaults.SYNC_CONTACT_DETAILS));
        properties.put(DELETE_USERS, String.valueOf(Defaults.DELETE_USERS));
        properties.put(PASSKEY_ENROLLED_CLAIM, "");
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {

        return null;
    }

    @Override
    public List<String> getConfidentialPropertyValues(String tenantDomain) {

        return Collections.singletonList(SECRET_KEY);
    }
}
