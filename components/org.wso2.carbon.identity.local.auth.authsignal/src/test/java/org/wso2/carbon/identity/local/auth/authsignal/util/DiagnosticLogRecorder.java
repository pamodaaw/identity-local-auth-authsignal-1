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
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;

/**
 * Enables diagnostic logs on a mocked {@link LoggerUtils} and records the logs triggered, instead of publishing them.
 */
public final class DiagnosticLogRecorder {

    private final List<DiagnosticLog> logs = new ArrayList<>();

    private DiagnosticLogRecorder(MockedStatic<LoggerUtils> loggerUtils) {

        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        loggerUtils.when(() -> LoggerUtils.triggerDiagnosticLogEvent(any(DiagnosticLog.DiagnosticLogBuilder.class)))
                .thenAnswer(invocation -> logs.add(
                        invocation.<DiagnosticLog.DiagnosticLogBuilder>getArgument(0).build()));
    }

    public static DiagnosticLogRecorder start(MockedStatic<LoggerUtils> loggerUtils) {

        return new DiagnosticLogRecorder(loggerUtils);
    }

    /**
     * @return Each log as "action ID | STATUS: message", in the order they were triggered.
     */
    public List<String> getLogs() {

        return logs.stream().map(log -> log.getActionId() + " | " + log.getResultStatus() + ": "
                + log.getResultMessage()).collect(Collectors.toList());
    }

    /**
     * @return The component ID of each log.
     */
    public List<String> getComponentIds() {

        return logs.stream().map(DiagnosticLog::getComponentId).collect(Collectors.toList());
    }

    /**
     * @return The input parameters of the first log with a message, or an empty map if there is no such log.
     */
    public Map<String, Object> getInputs(String message) {

        return logs.stream().filter(log -> message.equals(log.getResultMessage()))
                .map(DiagnosticLog::getInput).findFirst().orElse(Collections.emptyMap());
    }
}
