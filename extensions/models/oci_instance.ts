/**
 * Oracle Cloud Infrastructure (OCI) compute instance integration.
 *
 * Wraps the OCI Core Services API's `InstanceAction` and `GetInstance`
 * operations so a swamp model represents a single OCI compute VM. Exposes
 * `reboot` (SOFTRESET / RESET), `start`, `stop` (SOFTSTOP / STOP), and `sync`
 * (fetch current lifecycle state). Requests are authenticated with OCI's
 * RSA-SHA256 HTTP Signature scheme using an API signing key.
 *
 * API reference: https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/Instance/InstanceAction
 *
 * @module
 */
// extensions/models/oci_instance.ts
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  tenancyId: z.string().describe(
    "Tenancy OCID, e.g. ocid1.tenancy.oc1..aaaa...",
  ),
  userId: z.string().describe("User OCID, e.g. ocid1.user.oc1..aaaa..."),
  fingerprint: z.string().describe(
    "API signing-key fingerprint, e.g. 12:34:56:...:ab",
  ),
  privateKey: z.string().meta({ sensitive: true }).describe(
    "PEM-encoded RSA API signing private key (PKCS#8 or PKCS#1, unencrypted). Wire with a vault.get(...) expression.",
  ),
  region: z.string().describe(
    "OCI region identifier, e.g. us-ashburn-1, uk-london-1",
  ),
  instanceId: z.string().describe(
    "OCID of the compute instance this model manages, e.g. ocid1.instance.oc1..aaaa...",
  ),
  endpoint: z.string().optional().describe(
    "Override the IaaS API host. Defaults to iaas.<region>.oraclecloud.com (the OC1 commercial realm). Set for GovCloud or other realms.",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const RebootArgsSchema = z.object({
  action: z.enum(["SOFTRESET", "RESET"]).default("SOFTRESET").describe(
    "SOFTRESET sends an ACPI shutdown then powers the VM back on (graceful). RESET immediately power-cycles the VM (hard).",
  ),
});

const StopArgsSchema = z.object({
  action: z.enum(["SOFTSTOP", "STOP"]).default("SOFTSTOP").describe(
    "SOFTSTOP sends an ACPI shutdown (graceful). STOP immediately powers the VM off (hard).",
  ),
});

const InstanceSchema = z.object({
  id: z.string(),
  displayName: z.string().nullable().optional(),
  lifecycleState: z.string(),
  region: z.string(),
  availabilityDomain: z.string().nullable().optional(),
  shape: z.string().nullable().optional(),
  compartmentId: z.string().nullable().optional(),
  timeCreated: z.string().nullable().optional(),
  observedAt: z.string(),
});

const ActionSchema = z.object({
  instanceId: z.string(),
  action: z.string(),
  lifecycleState: z.string(),
  displayName: z.string().nullable().optional(),
  requestedAt: z.string(),
});

// ---------------------------------------------------------------------------
// OCI request signing (RSA-SHA256 HTTP Signatures)
//   https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
// ---------------------------------------------------------------------------

/** Base64-encode raw bytes. */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Decode a base64 string to raw bytes. */
function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** DER length encoding (short or long form). */
function derLength(length: number): number[] {
  if (length < 0x80) return [length];
  const bytes: number[] = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return [0x80 | bytes.length, ...bytes];
}

/**
 * Wrap a PKCS#1 RSAPrivateKey DER into a PKCS#8 PrivateKeyInfo DER so it can
 * be imported by Web Crypto (which only accepts PKCS#8 for RSA).
 */
function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  // AlgorithmIdentifier: SEQUENCE { OID rsaEncryption (1.2.840.113549.1.1.1), NULL }
  const algId = [
    0x30,
    0x0d,
    0x06,
    0x09,
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00,
  ];
  const version = [0x02, 0x01, 0x00]; // INTEGER 0
  const octetString = [0x04, ...derLength(pkcs1.length), ...pkcs1];
  const body = [...version, ...algId, ...octetString];
  const seq = [0x30, ...derLength(body.length), ...body];
  return new Uint8Array(seq);
}

/** Extract the DER bytes and format of a PEM private key. */
function pemToPkcs8Der(pem: string): Uint8Array {
  if (/ENCRYPTED/.test(pem)) {
    throw new Error(
      "OCI private key is encrypted; provide an unencrypted PEM key (Web Crypto cannot decrypt passphrase-protected keys).",
    );
  }
  const isPkcs1 = /BEGIN RSA PRIVATE KEY/.test(pem);
  const isPkcs8 = /BEGIN PRIVATE KEY/.test(pem);
  if (!isPkcs1 && !isPkcs8) {
    throw new Error(
      "OCI private key must be a PEM-encoded RSA key ('BEGIN PRIVATE KEY' or 'BEGIN RSA PRIVATE KEY').",
    );
  }
  const b64 = pem
    .replace(/-----BEGIN[^-]+-----/g, "")
    .replace(/-----END[^-]+-----/g, "")
    .replace(/\s+/g, "");
  const der = base64ToBytes(b64);
  return isPkcs1 ? pkcs1ToPkcs8(der) : der;
}

/** Import the OCI PEM signing key as an RSASSA-PKCS1-v1_5 / SHA-256 sign key. */
async function importSigningKey(pem: string): Promise<CryptoKey> {
  const der = pemToPkcs8Der(pem);
  return await crypto.subtle.importKey(
    "pkcs8",
    der.buffer as ArrayBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

/** Base64-encoded SHA-256 digest of the given bytes (OCI x-content-sha256). */
async function sha256Base64(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    data.buffer as ArrayBuffer,
  );
  return bytesToBase64(new Uint8Array(digest));
}

/**
 * Perform an OCI-signed HTTPS request and return the parsed JSON body.
 * Signs the minimal header set for GET, and additionally
 * x-content-sha256 / content-type / content-length for POST/PUT/PATCH.
 */
async function ociRequest(
  method: "GET" | "POST",
  url: string,
  body: Uint8Array | null,
  globalArgs: GlobalArgs,
  now: string,
): Promise<{ status: number; json: unknown; text: string }> {
  const u = new URL(url);
  const requestTarget = `${method.toLowerCase()} ${u.pathname}${u.search}`;

  const headersToSign = ["(request-target)", "x-date", "host"];
  const signingLines = [
    `(request-target): ${requestTarget}`,
    `x-date: ${now}`,
    `host: ${u.host}`,
  ];
  const fetchHeaders: Record<string, string> = { "x-date": now };

  if (method === "POST") {
    const payload = body ?? new Uint8Array();
    const contentSha = await sha256Base64(payload);
    headersToSign.push("x-content-sha256", "content-type", "content-length");
    signingLines.push(`x-content-sha256: ${contentSha}`);
    signingLines.push(`content-type: application/json`);
    signingLines.push(`content-length: ${payload.length}`);
    fetchHeaders["x-content-sha256"] = contentSha;
    fetchHeaders["content-type"] = "application/json";
    fetchHeaders["content-length"] = String(payload.length);
  }

  const signingString = signingLines.join("\n");
  const key = await importSigningKey(globalArgs.privateKey);
  const signatureBytes = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(signingString),
  );
  const signature = bytesToBase64(new Uint8Array(signatureBytes));
  const keyId =
    `${globalArgs.tenancyId}/${globalArgs.userId}/${globalArgs.fingerprint}`;
  fetchHeaders["authorization"] =
    `Signature version="1",keyId="${keyId}",algorithm="rsa-sha256",headers="${
      headersToSign.join(" ")
    }",signature="${signature}"`;

  const res = await fetch(url, {
    method,
    headers: fetchHeaders,
    body: method === "POST"
      ? ((body ?? new Uint8Array()) as BodyInit)
      : undefined,
  });
  const text = await res.text();
  let json: unknown = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  return { status: res.status, json, text };
}

/** Build the IaaS API host for a region (or honor an explicit override). */
function iaasHost(globalArgs: GlobalArgs): string {
  return globalArgs.endpoint ?? `iaas.${globalArgs.region}.oraclecloud.com`;
}

/** Fetch the current instance state via GetInstance. */
async function getInstance(
  globalArgs: GlobalArgs,
  now: string,
): Promise<Record<string, unknown>> {
  const url = `https://${iaasHost(globalArgs)}/20160918/instances/${
    encodeURIComponent(globalArgs.instanceId)
  }`;
  const { status, json, text } = await ociRequest(
    "GET",
    url,
    null,
    globalArgs,
    now,
  );
  if (status < 200 || status >= 300) {
    throw new Error(`OCI GetInstance failed (${status}): ${text}`);
  }
  return json as Record<string, unknown>;
}

/** Invoke InstanceAction with the given action verb. */
async function instanceAction(
  action: string,
  globalArgs: GlobalArgs,
  now: string,
): Promise<Record<string, unknown>> {
  const url = `https://${iaasHost(globalArgs)}/20160918/instances/${
    encodeURIComponent(globalArgs.instanceId)
  }?action=${encodeURIComponent(action)}`;
  const { status, json, text } = await ociRequest(
    "POST",
    url,
    new Uint8Array(),
    globalArgs,
    now,
  );
  if (status < 200 || status >= 300) {
    throw new Error(`OCI InstanceAction ${action} failed (${status}): ${text}`);
  }
  return json as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Context types
// ---------------------------------------------------------------------------

type Logger = {
  info: (message: string, props?: Record<string, unknown>) => void;
  warn: (message: string, props?: Record<string, unknown>) => void;
};

type ExecuteContext = {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
};

/** Map an OCI GetInstance response onto the stored `instance` resource shape. */
function toInstanceResource(
  instance: Record<string, unknown>,
  globalArgs: GlobalArgs,
  observedAt: string,
): Record<string, unknown> {
  return {
    id: (instance.id as string) ?? globalArgs.instanceId,
    displayName: (instance.displayName as string) ?? null,
    lifecycleState: (instance.lifecycleState as string) ?? "UNKNOWN",
    region: (instance.region as string) ?? globalArgs.region,
    availabilityDomain: (instance.availabilityDomain as string) ?? null,
    shape: (instance.shape as string) ?? null,
    compartmentId: (instance.compartmentId as string) ?? null,
    timeCreated: (instance.timeCreated as string) ?? null,
    observedAt,
  };
}

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

/**
 * OCI compute instance model — one model instance represents one VM, keyed by
 * its `instanceId` OCID. Exposes power-control methods plus `sync`.
 */
export const model = {
  type: "@sntxrr/oci-instance",
  version: "2026.07.17.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    "instance": {
      description: "Snapshot of the OCI compute instance's state",
      schema: InstanceSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "action": {
      description: "Record of a power-control action issued to the instance",
      schema: ActionSchema,
      lifetime: "infinite",
      garbageCollection: 50,
    },
  },
  methods: {
    reboot: {
      description:
        "Reboot the instance. SOFTRESET (default) gracefully shuts down then powers on; RESET hard power-cycles.",
      arguments: RebootArgsSchema,
      execute: async (
        args: z.infer<typeof RebootArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs, logger } = context;
        const now = new Date().toUTCString();
        logger.info("Rebooting OCI instance {id} with {action}", {
          id: globalArgs.instanceId,
          action: args.action,
        });
        const result = await instanceAction(args.action, globalArgs, now);
        const handle = await context.writeResource("action", "latest", {
          instanceId: globalArgs.instanceId,
          action: args.action,
          lifecycleState: (result.lifecycleState as string) ?? "UNKNOWN",
          displayName: (result.displayName as string) ?? null,
          requestedAt: new Date().toISOString(),
        });
        logger.info("Instance {id} now {state}", {
          id: globalArgs.instanceId,
          state: (result.lifecycleState as string) ?? "UNKNOWN",
        });
        return { dataHandles: [handle] };
      },
    },
    start: {
      description: "Power on the instance (InstanceAction START).",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs, logger } = context;
        const now = new Date().toUTCString();
        logger.info("Starting OCI instance {id}", {
          id: globalArgs.instanceId,
        });
        const result = await instanceAction("START", globalArgs, now);
        const handle = await context.writeResource("action", "latest", {
          instanceId: globalArgs.instanceId,
          action: "START",
          lifecycleState: (result.lifecycleState as string) ?? "UNKNOWN",
          displayName: (result.displayName as string) ?? null,
          requestedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    stop: {
      description:
        "Power off the instance. SOFTSTOP (default) gracefully shuts down; STOP hard powers off.",
      arguments: StopArgsSchema,
      execute: async (
        args: z.infer<typeof StopArgsSchema>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs, logger } = context;
        const now = new Date().toUTCString();
        logger.info("Stopping OCI instance {id} with {action}", {
          id: globalArgs.instanceId,
          action: args.action,
        });
        const result = await instanceAction(args.action, globalArgs, now);
        const handle = await context.writeResource("action", "latest", {
          instanceId: globalArgs.instanceId,
          action: args.action,
          lifecycleState: (result.lifecycleState as string) ?? "UNKNOWN",
          displayName: (result.displayName as string) ?? null,
          requestedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    sync: {
      description:
        "Fetch the instance's current lifecycle state and details (GetInstance).",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { globalArgs, logger } = context;
        const now = new Date().toUTCString();
        logger.info("Syncing OCI instance {id}", { id: globalArgs.instanceId });
        const instance = await getInstance(globalArgs, now);
        const handle = await context.writeResource(
          "instance",
          "latest",
          toInstanceResource(instance, globalArgs, new Date().toISOString()),
        );
        logger.info("Instance {id} is {state}", {
          id: globalArgs.instanceId,
          state: (instance.lifecycleState as string) ?? "UNKNOWN",
        });
        return { dataHandles: [handle] };
      },
    },
  },
};

/** Internal signing/encoding primitives, exported only for unit testing. */
export const _internal = {
  pkcs1ToPkcs8,
  pemToPkcs8Der,
  importSigningKey,
  sha256Base64,
  bytesToBase64,
  base64ToBytes,
  derLength,
  iaasHost,
};
