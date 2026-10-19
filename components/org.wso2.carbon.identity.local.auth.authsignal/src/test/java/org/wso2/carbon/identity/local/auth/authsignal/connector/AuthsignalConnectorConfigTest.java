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

import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Properties;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Tests for {@link AuthsignalConnectorConfig}.
 */
public class AuthsignalConnectorConfigTest {

    private final AuthsignalConnectorConfig connector = new AuthsignalConnectorConfig();

    @Test
    public void testEveryPropertyHasMetadataAndDefault() throws Exception {

        Properties defaults = connector.getDefaultPropertyValues("carbon.super");
        for (String name : connector.getPropertyNames()) {
            assertTrue(connector.getPropertyNameMapping().containsKey(name), "Missing display name: " + name);
            assertTrue(connector.getPropertyDescriptionMapping().containsKey(name), "Missing description: " + name);
            assertTrue(defaults.containsKey(name), "Missing default: " + name);
        }
        assertEquals(defaults.size(), connector.getPropertyNames().length);
        assertEquals(defaults.getProperty(AuthsignalConnectorConfig.REGION), "us");
        assertEquals(defaults.getProperty(AuthsignalConnectorConfig.SECRET_KEY), "");
        assertEquals(defaults.getProperty(AuthsignalConnectorConfig.SIGN_IN_FLOW_REF), "sign-in");
        assertEquals(defaults.getProperty(AuthsignalConnectorConfig.REGISTRATION_FLOW_REF), "sign-up");
        assertEquals(defaults.getProperty(AuthsignalConnectorConfig.RECOVERY_FLOW_REF), "password-reset");
        assertEquals(AuthsignalConnectorConfig.RECOVERY_FLOW_REF, "Authsignal.RecoveryFlowRef");
        // No claim is updated unless one is configured.
        assertEquals(defaults.getProperty(AuthsignalConnectorConfig.PASSKEY_ENROLLED_CLAIM), "");
    }

    @Test
    public void testSecretKeyIsConfidential() {

        assertEquals(connector.getConfidentialPropertyValues("carbon.super"),
                Collections.singletonList(AuthsignalConnectorConfig.SECRET_KEY));
        assertTrue(Arrays.asList(connector.getPropertyNames()).contains(AuthsignalConnectorConfig.SECRET_KEY));
    }
}
