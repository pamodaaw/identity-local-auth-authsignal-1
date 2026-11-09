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

package org.wso2.carbon.identity.local.auth.authsignal.exception;

import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.ErrorMessages;

/**
 * Thrown when an Authsignal API call fails or the client cannot be created.
 */
public class AuthsignalConnectionException extends Exception {

    private static final long serialVersionUID = -3518326203626380187L;

    // HTTP status returned by Authsignal, or -1 when no response was received.
    private final int statusCode;
    // Error code of a configuration error, or null when the API call failed.
    private final String errorCode;

    public AuthsignalConnectionException(String message) {

        this(message, -1);
    }

    public AuthsignalConnectionException(String message, int statusCode) {

        super(message);
        this.statusCode = statusCode;
        this.errorCode = null;
    }

    public AuthsignalConnectionException(String message, Throwable cause) {

        super(message, cause);
        this.statusCode = -1;
        this.errorCode = null;
    }

    public AuthsignalConnectionException(ErrorMessages error, String message) {

        super(message);
        this.statusCode = -1;
        this.errorCode = error.getCode();
    }

    public int getStatusCode() {

        return statusCode;
    }

    public String getErrorCode() {

        return errorCode;
    }

    /**
     * @return Whether Authsignal rejected the request with a 4xx status.
     */
    public boolean isClientError() {

        return statusCode >= 400 && statusCode < 500;
    }

    /**
     * @return Whether the call may succeed if retried: no response, rate limited or a server error.
     */
    public boolean isTransient() {

        return errorCode == null && (statusCode == -1 || statusCode == 429 || statusCode >= 500);
    }
}
