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

# Authsignal settings of one IS tenant or Asgardeo root organisation.
#
# + name - IS tenant domain or Asgardeo root organisation name, as sent in the event's `tenant.name`
# + webhookSecret - Secret of the webhook in Console > Webhooks, used to verify `x-hub-signature`
# + region - Authsignal region of the tenant: us, eu, au, ca or uk
# + authsignalSecretKey - Authsignal Server API secret key
# + syncContactDetails - Whether email and mobile changes are synced to Authsignal
# + requireVerifiedContactDetails - Whether an email or mobile change is synced only when the same update marks it as
# verified. When false, every change is synced. Either way Authsignal stores the value as verified.
# + deleteUsers - Whether users deleted in WSO2 are deleted on Authsignal
public type TenantConfig record {|
    string name;
    string webhookSecret;
    string region = "us";
    string authsignalSecretKey;
    boolean syncContactDetails = true;
    boolean requireVerifiedContactDetails = true;
    boolean deleteUsers = true;
|};

# Port the service listens on.
configurable int port = 9090;

# One entry per IS tenant or Asgardeo root organisation that sends webhooks to this service.
configurable TenantConfig[] tenants = [];

# Attempts per Authsignal call, including the first one.
configurable int maxAttempts = 3;

# Timeout of an Authsignal call, in seconds.
configurable decimal requestTimeout = 5;

# Authsignal base URL to use instead of the region's, for example a local mock. Empty uses the region.
configurable string authsignalBaseUrl = "";

final readonly & map<string> REGION_BASE_URLS = {
    us: "https://api.authsignal.com/v1",
    eu: "https://eu.api.authsignal.com/v1",
    au: "https://au.api.authsignal.com/v1",
    ca: "https://ca.api.authsignal.com/v1",
    uk: "https://uk.api.authsignal.com/v1"
};

function init() returns error? {

    foreach TenantConfig tenant in tenants {
        if !REGION_BASE_URLS.hasKey(tenant.region.toLowerAscii()) {
            return error(string `Invalid Authsignal region '${tenant.region}' for tenant '${tenant.name}'.`);
        }
    }
}

# Get the settings of a tenant.
#
# + name - Tenant domain or root organisation name
# + return - Settings of the tenant, or nil if the tenant is not configured
isolated function findTenant(string name) returns TenantConfig? {

    foreach TenantConfig tenant in tenants {
        if tenant.name.equalsIgnoreCaseAscii(name) {
            return tenant;
        }
    }
    return ();
}
