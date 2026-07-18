# swamp-oci

A [swamp](https://swamp-club.com) extension repo for **Oracle Cloud
Infrastructure (OCI)**.

## Extensions

### [`@sntxrr/oci-instance`](./extensions/models/README.md)

Power-control an OCI compute instance — one model instance per VM, keyed by its
instance OCID. Authenticated with OCI's RSA-SHA256 HTTP Signature scheme (API
signing key) using only Deno's built-in `fetch` and Web Crypto — no external
SDK.

| Method   | What it does                                             |
| -------- | -------------------------------------------------------- |
| `reboot` | `SOFTRESET` (graceful, default) or `RESET` (hard)        |
| `start`  | Power the instance on                                    |
| `stop`   | `SOFTSTOP` (graceful, default) or `STOP` (hard)          |
| `sync`   | Fetch current lifecycle state (`GetInstance`)            |

Full usage, arguments, and setup are in the
[extension README](./extensions/models/README.md).

## Quick start

```bash
# Store your OCI API signing key in a vault
swamp vault create local_encryption oci
swamp vault put oci OCI_PRIVATE_KEY < ~/.oci/oci_api_key.pem

# Register a VM (wire the key from the vault)
swamp model create @sntxrr/oci-instance web-1 \
  --global-arg 'tenancyId=ocid1.tenancy.oc1..REPLACE' \
  --global-arg 'userId=ocid1.user.oc1..REPLACE' \
  --global-arg 'fingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99' \
  --global-arg 'region=us-ashburn-1' \
  --global-arg 'instanceId=ocid1.instance.oc1..REPLACE' \
  --global-arg 'privateKey=${{ vault.get(oci, OCI_PRIVATE_KEY) }}'

# Reboot it
swamp model @sntxrr/oci-instance method run reboot web-1                 # graceful
swamp model @sntxrr/oci-instance method run reboot web-1 --input action=RESET  # hard
```

## Development

```bash
~/.swamp/deno/deno check extensions/models/oci_instance.ts
~/.swamp/deno/deno test  extensions/models/oci_instance_test.ts
swamp extension quality  extensions/models/manifest.yaml --json
```

## License

MIT — see [LICENSE.md](./extensions/models/LICENSE.md).
