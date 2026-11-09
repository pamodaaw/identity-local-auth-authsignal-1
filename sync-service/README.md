# Authsignal Sync Service

A small Ballerina service, deployed on [Choreo](https://console.choreo.dev), that keeps Authsignal's users in step with
WSO2 Identity Server (7.2 or later) or Asgardeo. It receives the platform's
[webhooks](https://wso2.com/identity-platform/docs/guides/webhooks/setup-webhooks/) and calls the Authsignal Server API:

| Webhook event        | Result in Authsignal                                                           |
|----------------------|--------------------------------------------------------------------------------|
| User profile updated | The changed email address and mobile number are set as verified on the Authsignal user |
| User deleted         | The Authsignal user and their authenticators are deleted                       |

The service holds no state and never calls back into WSO2 IS or Asgardeo, so it needs no application or credentials
there. One deployment can serve several IS tenants or Asgardeo organisations.

## What is synced

A profile update event carries only the claims that changed. By default the service syncs a value only when the same
update also marks it as verified:

- **Email**: `http://wso2.org/claims/emailaddress` together with `http://wso2.org/claims/identity/emailVerified = true`.
- **Mobile**: `http://wso2.org/claims/mobile` (E.164, for example `+94771234567`) together with
  `http://wso2.org/claims/identity/phoneVerified = true`.

This is how the email and mobile verification flows write them. The values are sent to Authsignal's
[Update User](https://docs.authsignal.com/api-reference/server-api/update-user) API marked as verified, which moves the
user's email and SMS authenticators to the new values without an OTP.

To sync changes that carry no verified flag, for example when the verified claims are not used, or an administrator
edits an email address, set `requireVerifiedContactDetails = false` on the tenant. Every changed email and mobile is
then synced, whatever its verified flag, and is still marked as verified on Authsignal. Only turn this off when the
values in WSO2 can be trusted, since a user who can edit their own email or mobile would otherwise move their
Authsignal email and SMS authenticators to an address or number they have not proven.

The service first reads the user from Authsignal and writes only what differs, so redelivered events cause no further
writes. Users with no authenticators on Authsignal are skipped.

Not synced:

- With `requireVerifiedContactDetails = true`, a changed value whose verified flag is not part of the same update, for
  example an administrator editing an email address that was already verified.
- A verified flag that changes without the value.
- Removed values.

The platform retries deliveries that fail, but a late retry of an older event can still overwrite a newer value.

## How it works

| Request | Response |
|---|---|
| `GET /events?hub.challenge=…` | WebSub verification when the webhook is activated or deactivated. Echoes `hub.challenge` if `hub.topic` belongs to a configured tenant, otherwise 404. |
| `POST /events` | A delivery. The tenant is read from the event's `tenant.name`, and `x-hub-signature` (`sha256=` HMAC of the raw body) is checked with that tenant's webhook secret. 401 on a bad signature, 503 when Authsignal could not be updated after retries (the platform then redelivers), 200 otherwise, including events and tenants the service ignores. |
| `GET /healthz` | 200 `OK`. |

Logs carry the tenant and event ID only, never email addresses, phone numbers or user IDs.

## Configuration

Each IS tenant or Asgardeo organisation is one `tenants` entry:

| Key | Default | Description |
|---|---|---|
| `name` | required | IS tenant domain (`carbon.super` for the super tenant) or Asgardeo organisation name |
| `webhookSecret` | required | Secret of the webhook in Console > Webhooks. **Secret.** |
| `region` | `us` | Authsignal region: `us`, `eu`, `au`, `ca` or `uk` |
| `authsignalSecretKey` | required | Authsignal Server API secret key. **Secret.** |
| `syncContactDetails` | `true` | Sync email and mobile changes |
| `requireVerifiedContactDetails` | `true` | Sync a change only when the same update marks it as verified. `false` syncs every change. Authsignal stores the value as verified either way. |
| `deleteUsers` | `true` | Delete users on Authsignal when they are deleted in WSO2 |

Service-wide settings: `port` (9090), `maxAttempts` (3, attempts per Authsignal call), `requestTimeout` (5 seconds).

See [Config.toml.example](Config.toml.example).

## Deploy on Choreo

### Prerequisites

- A Choreo organisation and project.
- An Authsignal tenant, its region and its Server API secret key (Authsignal Portal > Settings > API keys).
- WSO2 IS 7.2 or later reachable from Choreo, or an Asgardeo organisation.

### 1. Create the component

1. In the Choreo Console, open your project and click **Create** > **Service**.
2. Connect this GitHub repository and select the branch.
3. Set **Buildpack** to **Ballerina** and **Project Directory** to `sync-service`. Choreo reads the endpoint
   (port 9090, base path `/`, public) from [.choreo/component.yaml](.choreo/component.yaml).
4. Give the component a name, for example `authsignal-sync`, and click **Create**.

### 2. Build and deploy

1. Open **Build** and build the latest commit.
2. Open **Deploy**, click **Configure & Deploy** on the Development environment, and fill in the configurables:
   one `tenants` entry per tenant (see [Configuration](#configuration)). Store `webhookSecret` and
   `authsignalSecretKey` as secrets.
3. Deploy, and wait for the deployment to become active.

### 3. Let the platform reach the endpoint

The platform cannot send a Choreo access token; the HMAC signature authenticates each delivery instead. In the
component's **Manage** > **Settings**, turn off OAuth2 security for the `GET /events` and `POST /events` resources,
then redeploy so the change takes effect. Copy the public endpoint URL from the **Overview** page.

### 4. Create the webhook

In the WSO2 IS Console or the Asgardeo Console:

1. Go to **Webhooks** > **Add Webhook**.
2. **Endpoint**: `<public endpoint URL>/events`.
3. **Secret**: the same value as `webhookSecret` for this tenant.
4. **Events**: under user account management, select **User profile updated** and **User deleted**.
5. Click **Create**, then switch the webhook on. The platform sends the verification request and the service answers
   it. If activation fails, check the service logs in Choreo (**Observe**), fix the cause and use **Resend
   subscription** on the webhook.

### 5. Check it

1. Sign in to My Account as a user who has authenticators on Authsignal, change the email address and verify it.
   The Authsignal Portal shows the new email address as verified on that user.
2. Delete a test user in the Console. The user is gone from Authsignal.

Then promote the component to Production in **Deploy** and point the production webhook at the production URL.

### Operations

- **Rotate secrets** in both places together: the webhook secret in the Console and in Choreo; the Authsignal key in the
  Authsignal Portal and in Choreo.
- **Add a tenant** by adding a `tenants` entry in Choreo and redeploying, then creating the webhook in that tenant.
- **Network**: if IS sits behind a firewall, allow outbound HTTPS to the Choreo endpoint. If the endpoint is restricted,
  allow the platform's outbound IP addresses.
- **Failures**: a 503 makes the platform redeliver; repeated failures show in the Choreo logs with the event ID (`jti`).

## Run locally

Requires [Ballerina](https://ballerina.io/downloads/) Swan Lake 2201.14.1 (see `Ballerina.toml`).

```bash
cp Config.toml.example Config.toml
```

Edit `Config.toml`, then:

```bash
bal run
```

To receive webhooks from a local IS, expose port 9090 with a tunnel (for example `ngrok http 9090`) and use the tunnel
URL as the webhook endpoint.

## Tests

```bash
bal test
```

The tests start the service on port 9090 and a mock Authsignal API on port 9091, using
[tests/Config.toml](tests/Config.toml).
