// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

# Get the Authsignal user ID of an event user, which is the WSO2 user ID, the same as the connector uses.
#
# + userId - WSO2 user ID from the event
# + return - Authsignal user ID, or nil if the event has no user ID
isolated function toAuthsignalUserId(string? userId) returns string? {

    return userId is string && userId.trim() != "" ? userId.trim() : ();
}
