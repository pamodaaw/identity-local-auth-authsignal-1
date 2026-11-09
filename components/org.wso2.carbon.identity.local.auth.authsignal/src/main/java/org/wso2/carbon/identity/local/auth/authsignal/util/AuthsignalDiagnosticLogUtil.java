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

import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.InputKeys;
import org.wso2.carbon.identity.local.auth.authsignal.exception.AuthsignalConnectionException;
import org.wso2.carbon.identity.local.auth.authsignal.model.AuthsignalResponse;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;

import static org.wso2.carbon.identity.local.auth.authsignal.constant.AuthsignalConstants.LogConstants.AUTHSIGNAL_SERVICE;

/**
 * Diagnostic logs of the Authsignal sign-in, flow executor and flow listener. The inputs are only built if diagnostic
 * logs are enabled. Only IDs, codes and states are logged, never personal data such as email addresses or mobile
 * numbers, and the user ID and claims are masked unless they are loggable.
 */
public final class AuthsignalDiagnosticLogUtil {

    private static final String USER_ID_CLAIM = "http://wso2.org/claims/userid";

    private AuthsignalDiagnosticLogUtil() {

    }

    /**
     * Trigger a success diagnostic log.
     *
     * @param actionId Action ID.
     * @param message  Result message.
     * @param inputs   Input parameters. Must not hold personal data.
     */
    public static void triggerSuccessLog(String actionId, String message, Supplier<Map<String, Object>> inputs) {

        triggerLog(actionId, message, DiagnosticLog.ResultStatus.SUCCESS, inputs);
    }

    /**
     * Trigger a failure diagnostic log, with the HTTP status if the failure was caused by Authsignal returning one.
     *
     * @param actionId Action ID.
     * @param message  Result message. Must not hold personal data.
     * @param cause    Cause of the failure, or null.
     * @param inputs   Input parameters. Must not hold personal data.
     */
    public static void triggerFailureLog(String actionId, String message, Throwable cause,
                                         Supplier<Map<String, Object>> inputs) {

        triggerLog(actionId, message, DiagnosticLog.ResultStatus.FAILED, () -> {
            Map<String, Object> params = inputs.get();
            AuthsignalConnectionException error = findConnectionError(cause);
            if (error != null && error.getStatusCode() > 0) {
                params.put(InputKeys.STATUS_CODE, error.getStatusCode());
            }
            return params;
        });
    }

    /**
     * Get the inputs common to all logs: the action code of the Authsignal flow and the WSO2 user ID, which is also
     * the Authsignal user ID.
     *
     * @param actionCode Action code, or null if not known.
     * @param userId     WSO2 user ID, or null if not known.
     * @return Mutable map of the inputs.
     */
    public static Map<String, Object> commonInputs(String actionCode, String userId) {

        Map<String, Object> inputs = new HashMap<>();
        putIfNotNull(inputs, InputKeys.ACTION_CODE, actionCode);
        if (userId != null) {
            inputs.put(LogConstants.InputKeys.USER_ID, LoggerUtils.isLogMaskingEnable
                    ? LoggerUtils.getMaskedClaimValue(USER_ID_CLAIM, userId) : userId);
        }
        return inputs;
    }

    /**
     * Add the flow state and the verification methods the user completed, from a Verify Flow response.
     *
     * @param inputs Inputs to add to.
     * @param result Verify Flow response.
     * @return The inputs.
     */
    public static Map<String, Object> addFlowResult(Map<String, Object> inputs, AuthsignalResponse result) {

        putIfNotNull(inputs, InputKeys.FLOW_STATE, result.getState());
        if (!result.getVerificationMethods().isEmpty()) {
            inputs.put(InputKeys.VERIFICATION_METHODS, result.getVerificationMethods());
        }
        return inputs;
    }

    /**
     * Add the claims updated on a user. Claims that are not loggable are masked.
     *
     * @param inputs Inputs to add to.
     * @param claims Claims updated on the user.
     * @return The inputs.
     */
    public static Map<String, Object> addUpdatedClaims(Map<String, Object> inputs, Map<String, String> claims) {

        if (!claims.isEmpty()) {
            inputs.put(InputKeys.UPDATED_CLAIMS,
                    new TreeMap<>(LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedClaimsMap(claims) : claims));
        }
        return inputs;
    }

    /**
     * Add an input if the value is not null.
     */
    public static void putIfNotNull(Map<String, Object> inputs, String key, Object value) {

        if (value != null) {
            inputs.put(key, value);
        }
    }

    private static void triggerLog(String actionId, String message, DiagnosticLog.ResultStatus status,
                                   Supplier<Map<String, Object>> inputs) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder =
                new DiagnosticLog.DiagnosticLogBuilder(AUTHSIGNAL_SERVICE, actionId)
                        .resultMessage(message)
                        .resultStatus(status)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .inputParams(inputs.get());
        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
    }

    private static AuthsignalConnectionException findConnectionError(Throwable cause) {

        for (Throwable error = cause; error != null; error = error.getCause()) {
            if (error instanceof AuthsignalConnectionException) {
                return (AuthsignalConnectionException) error;
            }
        }
        return null;
    }
}
