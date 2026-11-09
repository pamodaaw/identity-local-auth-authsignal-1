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

package org.wso2.carbon.identity.local.auth.authsignal.util;

import org.mockito.MockedStatic;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mockStatic;

/**
 * Records claim updates made through {@link AuthsignalUtil#setUserClaims} instead of saving them, and serves
 * {@link AuthsignalUtil#getUserClaim} from stored values.
 */
public final class ClaimUpdateRecorder implements AutoCloseable {

    private final MockedStatic<AuthsignalUtil> mock;
    private String username;
    private Map<String, String> claims;
    private final Map<String, String> storedClaims = new HashMap<>();
    private UserStoreException failure;
    private Runnable onUpdate;

    private ClaimUpdateRecorder() {

        mock = mockStatic(AuthsignalUtil.class, invocation -> {
            if ("getUserClaim".equals(invocation.getMethod().getName())) {
                return storedClaims.get(invocation.<String>getArgument(2));
            }
            if (!"setUserClaims".equals(invocation.getMethod().getName())) {
                return invocation.callRealMethod();
            }
            if (failure != null) {
                throw failure;
            }
            username = invocation.getArgument(1);
            claims = invocation.getArgument(2);
            // Like the SCIM listener, which adds the last modified time.
            claims.put("probe", "probe");
            claims.remove("probe");
            if (onUpdate != null) {
                onUpdate.run();
            }
            return null;
        });
    }

    /**
     * Start recording claim updates on the current thread. Close the recorder to stop.
     */
    public static ClaimUpdateRecorder start() {

        return new ClaimUpdateRecorder();
    }

    /**
     * Set a claim value returned when the claim is read.
     */
    public void storeClaim(String claimUri, String value) {

        storedClaims.put(claimUri, value);
    }

    /**
     * Fail the following claim updates with the given exception.
     */
    public void failWith(UserStoreException failure) {

        this.failure = failure;
    }

    /**
     * Run the given action whenever claims are updated.
     */
    public void onUpdate(Runnable onUpdate) {

        this.onUpdate = onUpdate;
    }

    /**
     * @return Domain qualified username of the last claim update, or null if there was none.
     */
    public String getUsername() {

        return username;
    }

    /**
     * @return Claims of the last claim update, or null if there was none.
     */
    public Map<String, String> getClaims() {

        return claims;
    }

    @Override
    public void close() {

        mock.close();
    }
}
