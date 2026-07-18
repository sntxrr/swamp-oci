# @sntxrr/oci-instance

A [swamp](https://swamp-club.com) model for power-controlling **Oracle Cloud
Infrastructure (OCI) compute instances**. One model instance represents one VM,
identified by its instance OCID. Modeled after the `@swamp/aws/*` cloud
extensions.

Requests are authenticated with OCI's RSA-SHA256 HTTP Signature scheme using an
API signing key — no external SDK, just Deno's built-in `fetch` and Web Crypto.

## Methods

| Method   | Arguments                       | OCI operation                          |
| -------- | ------------------------------- | -------------------------------------- |
| `reboot` | `action` = `SOFTRESET`\*/`RESET`  | `InstanceAction` — SOFTRESET / RESET   |
| `start`  | —                               | `InstanceAction` — START               |
| `stop`   | `action` = `SOFTSTOP`\*/`STOP`    | `InstanceAction` — SOFTSTOP / STOP     |
| `sync`   | —                               | `GetInstance` (lifecycle state)        |

\* default. `SOFTRESET`/`SOFTSTOP` issue an ACPI graceful shutdown; `RESET`/`STOP`
hard power-cycle/power-off immediately.

## Global arguments

| Argument      | Required | Description                                                        |
| ------------- | -------- | ------------------------------------------------------------------ |
| `tenancyId`   | yes      | Tenancy OCID (`ocid1.tenancy.oc1..…`)                              |
| `userId`      | yes      | User OCID (`ocid1.user.oc1..…`)                                    |
| `fingerprint` | yes      | API signing-key fingerprint (`12:34:…:ab`)                        |
| `privateKey`  | yes      | PEM RSA signing key (PKCS#8 or PKCS#1, **unencrypted**). Use a vault. |
| `region`      | yes      | Region id, e.g. `us-ashburn-1`                                     |
| `instanceId`  | yes      | Instance OCID this model manages (`ocid1.instance.oc1..…`)        |
| `endpoint`    | no       | Override IaaS host. Defaults to `iaas.<region>.oraclecloud.com`.   |

## Setup

Store the signing key in a vault so it never lands in a committed model
definition:

```bash
swamp vault create env oci                 # or any vault backend
swamp vault put oci OCI_PRIVATE_KEY --file ~/.oci/oci_api_key.pem
```

Create a model per VM (the `name` is the swamp-local handle):

```bash
swamp model create @sntxrr/oci-instance web-1
```

Then set its global arguments — `tenancyId`, `userId`, `fingerprint`, `region`,
`instanceId`, and wire `privateKey` to `vault.get("oci", "OCI_PRIVATE_KEY")`.

## Usage

```bash
# Check current state first
swamp model @sntxrr/oci-instance method run sync web-1
swamp data get web-1

# Graceful reboot (default)
swamp model @sntxrr/oci-instance method run reboot web-1

# Hard reset
swamp model @sntxrr/oci-instance method run reboot web-1 --action RESET

# Power off / on
swamp model @sntxrr/oci-instance method run stop web-1
swamp model @sntxrr/oci-instance method run start web-1
```

## Data resources

- **`instance`** — snapshot from `sync`: `lifecycleState`, `displayName`,
  `shape`, `availabilityDomain`, `compartmentId`, `timeCreated`, `observedAt`.
- **`action`** — record of the last power-control action: `action`,
  `lifecycleState`, `requestedAt`.

## Credentials

Set up an API signing key in the OCI console (Identity → Users → your user →
API Keys → Add API Key). OCI shows the config snippet with your `tenancy`,
`user`, `fingerprint`, and `region`. The private key must be **unencrypted** —
Web Crypto cannot decrypt passphrase-protected PEM keys.

## License

MIT — see [LICENSE.md](./LICENSE.md).
