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

const SUPER_TENANT_DOMAIN = "carbon.super";

# Get the Authsignal user ID of an event user, the same way the connector's AuthsignalUserIdResolver does.
#
# + tenant - Tenant settings
# + userId - WSO2 user ID from the event
# + username - Username from the event, with or without the user store domain
# + userStore - User store name from the event
# + return - Authsignal user ID, or nil if the event lacks what the tenant's identifier needs
isolated function toAuthsignalUserId(TenantConfig tenant, string? userId, string? username, string? userStore)
        returns string? {

    if tenant.userIdentifier == USER_ID {
        return userId is string && userId.trim() != "" ? userId.trim() : ();
    }
    if username is () || username.trim() == "" {
        return ();
    }
    string name = username.trim();
    string? domain = userStore;
    int? separator = name.indexOf("/");
    if separator is int {
        domain = name.substring(0, separator);
        name = name.substring(separator + 1);
    }
    return toQualifiedUsername(name, domain, tenant.name, tenant.primaryUserStore);
}

# Build a username based Authsignal user ID in the form `[DOMAIN/]username[@tenant]`. The primary user store and the
# super tenant are left out.
#
# + username - Username without the user store domain
# + userStore - User store domain of the user
# + tenantDomain - Tenant domain of the user
# + primaryUserStore - Name of the primary user store
# + return - Authsignal user ID
isolated function toQualifiedUsername(string username, string? userStore, string tenantDomain,
        string primaryUserStore) returns string {

    string qualified = username;
    if userStore is string && userStore.trim() != "" && !userStore.equalsIgnoreCaseAscii(primaryUserStore) {
        qualified = userStore.trim() + "/" + qualified;
    }
    if tenantDomain.trim() != "" && !tenantDomain.equalsIgnoreCaseAscii(SUPER_TENANT_DOMAIN) {
        qualified = qualified + "@" + tenantDomain;
    }
    return qualified;
}
