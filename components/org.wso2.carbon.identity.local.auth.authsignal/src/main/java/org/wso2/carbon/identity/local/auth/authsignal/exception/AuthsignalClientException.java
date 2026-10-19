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
 * Thrown when a call to the Authsignal Server API fails, or the client cannot be created from the configuration.
 */
public class AuthsignalClientException extends Exception {

    private static final long serialVersionUID = -3518326203626380187L;

    // HTTP status returned by Authsignal, or -1 when no response was received.
    private final int statusCode;
    // Error code of a configuration error, or null when the API call failed.
    private final String errorCode;

    public AuthsignalClientException(String message) {

        this(message, -1);
    }

    public AuthsignalClientException(String message, int statusCode) {

        super(message);
        this.statusCode = statusCode;
        this.errorCode = null;
    }

    public AuthsignalClientException(String message, Throwable cause) {

        super(message, cause);
        this.statusCode = -1;
        this.errorCode = null;
    }

    public AuthsignalClientException(ErrorMessages error, String message) {

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
}
