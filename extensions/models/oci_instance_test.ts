/**
 * Unit tests for the OCI signing primitives in oci_instance.ts.
 *
 * These validate the crypto plumbing (PEM parsing, PKCS#1→PKCS#8 conversion,
 * SHA-256 digesting, base64) without hitting the live OCI API: a signature
 * produced by the imported key is verified against the matching public key,
 * proving the full sign path is cryptographically sound.
 *
 * @module
 */
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { _internal, model } from "./oci_instance.ts";

// A throwaway 2048-bit RSA test key (never used against a real tenancy).
const PKCS1_PEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3NUKZi3mvI9/soliuUSl69QhyBcUPMNEresgRWk3lTbz7MwO
aOqFJkVyn7eu9Jp5owIAcfZ8uA8uGrWNLws6EzGYOEYd6rUgaOBDw1ipWtjtPPE4
K0GkYOT1HNSqiD1oHbe640BZgHYJyIDbrrMy0POHN6WN90u7QDcHvSIyY6wWfSvG
jf//VG4BawA95Z27MFgCcFL92r2ODiIlq3ClXGASt6J14S6mPoyV7QXQEc38zPxB
rBRJgsXfsmgoC4I1r7oBH8+O5C+hcRog6PzlNRhkFUVXvY7v96LEmj6n350LfE7W
WJQVjzubdHJQpIxXrdjIjktLJgxMDgOvMcmoKQIDAQABAoIBABpDM9NnDhPKtRMU
h6sk4N6lAcd8ByoaxuYwGkxm8PdL68JzmhscGO2uQK2B+MqaPHEIYekruTViiMcg
ZEP9/9Aci8/VduVc2Rff4+8tciaduckPnvB2BAiJ8iSVnhpJw0IVgaJZGsvOPeec
e4PRR+/VpnUVuUZ5uTEv2jnCAWAc9H55hZp9Gq+8rKBxUY9bo7DT2YKBWi7Xl+Ho
tnxOEFbfJ8fgFkPc1VhsDXVJIKJ6KCXVGeoN8KGhFeJ103vQm/jtuIswBu2BBe2L
/V6qusOkXxw7VEjgWTSRCsoHLHvk7VBTF9/3xWwinfRmJXBwLFu79m/cZUrxd5IY
aCvWB8kCgYEA/OBLwt7lxmVSjOViGO/HHQY29rEcOrFesDP5+ZMGk+76IwCwuLpM
zksVyRy4u8wYclBb+LAwuy35GGO5hRuWd3syxEzy6Mwx+2UU320tLNq6OrRzIQN8
aEc0E6UN4bf+qwRFXxYWb7g0sqXKtp3xGl4b/u4Uh5vNG4CUxV7vA0sCgYEA349o
YzL84qdC/VIeC7ZoFxZe+2DJbdJm/RJvXnKGbPh72x6LUjUquLTQaEL6tGAoJvbn
G+GuyHuAZS3YjK32p59aUmgHWDLtDBzn7WB6/ygCwo0VM8OTrUzmy+v+s0Ql7K3k
A97ZLRoYxkkqh76ONNceAWddBixIb28E0BCIJdsCgYEAlSyn5MRjHh+FjDKBJR7G
Ajw5Tlv6wDEEH8P5sh3monw2uVFd7wuP5Z5rsqEr5TUoMr9vEgy2IqWjLZ0ewwQc
Rk26DA0suuJClf/yST95h91cQOdUh2QsDsP6V6BlyQMmy7IQTmCUScGL7Nta81HG
+nwL3d6K49ioLZIzsR8otnMCgYATg/hP2I6c1o8RgA6hZR33Dfvio9NRo/FbnDVe
oE69yn89ZJAy7/M3xoj+4QHzpwU6SYlpNK1GUQmnS3ZA6ZrDjTScRvqFJ4Tr7sYM
QcTa60o6Y4h7SVJl6XWoTYShb4yD+bYS5Gw+9K0++fodeXP+htzWsIg9VrZIC//2
jcrkywKBgDiAqNkUHa2NeWpfZPWH4keGFijZSDpEgdudAL0SUalopdp6eefsKB0n
MZvDCOsWqBHu48Ei+cgjS0FCjqvVeTLB+nS9ZoIddEWb2BOUg7PPkCKTJjbU2wQk
/iUqTq/qAdQ2B5oGRvey3+sSX4RmT5xxaaiv/5p+gAzzpGmSi+2h
-----END RSA PRIVATE KEY-----`;

// PKCS#8 form of the exact same key.
const PKCS8_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDc1QpmLea8j3+y
iWK5RKXr1CHIFxQ8w0St6yBFaTeVNvPszA5o6oUmRXKft670mnmjAgBx9ny4Dy4a
tY0vCzoTMZg4Rh3qtSBo4EPDWKla2O088TgrQaRg5PUc1KqIPWgdt7rjQFmAdgnI
gNuuszLQ84c3pY33S7tANwe9IjJjrBZ9K8aN//9UbgFrAD3lnbswWAJwUv3avY4O
IiWrcKVcYBK3onXhLqY+jJXtBdARzfzM/EGsFEmCxd+yaCgLgjWvugEfz47kL6Fx
GiDo/OU1GGQVRVe9ju/3osSaPqffnQt8TtZYlBWPO5t0clCkjFet2MiOS0smDEwO
A68xyagpAgMBAAECggEAGkMz02cOE8q1ExSHqyTg3qUBx3wHKhrG5jAaTGbw90vr
wnOaGxwY7a5ArYH4ypo8cQhh6Su5NWKIxyBkQ/3/0ByLz9V25VzZF9/j7y1yJp25
yQ+e8HYECInyJJWeGknDQhWBolkay84955x7g9FH79WmdRW5Rnm5MS/aOcIBYBz0
fnmFmn0ar7ysoHFRj1ujsNPZgoFaLteX4ei2fE4QVt8nx+AWQ9zVWGwNdUkgonoo
JdUZ6g3woaEV4nXTe9Cb+O24izAG7YEF7Yv9Xqq6w6RfHDtUSOBZNJEKygcse+Tt
UFMX3/fFbCKd9GYlcHAsW7v2b9xlSvF3khhoK9YHyQKBgQD84EvC3uXGZVKM5WIY
78cdBjb2sRw6sV6wM/n5kwaT7vojALC4ukzOSxXJHLi7zBhyUFv4sDC7LfkYY7mF
G5Z3ezLETPLozDH7ZRTfbS0s2ro6tHMhA3xoRzQTpQ3ht/6rBEVfFhZvuDSypcq2
nfEaXhv+7hSHm80bgJTFXu8DSwKBgQDfj2hjMvzip0L9Uh4LtmgXFl77YMlt0mb9
Em9ecoZs+HvbHotSNSq4tNBoQvq0YCgm9ucb4a7Ie4BlLdiMrfann1pSaAdYMu0M
HOftYHr/KALCjRUzw5OtTObL6/6zRCXsreQD3tktGhjGSSqHvo401x4BZ10GLEhv
bwTQEIgl2wKBgQCVLKfkxGMeH4WMMoElHsYCPDlOW/rAMQQfw/myHeaifDa5UV3v
C4/lnmuyoSvlNSgyv28SDLYipaMtnR7DBBxGTboMDSy64kKV//JJP3mH3VxA51SH
ZCwOw/pXoGXJAybLshBOYJRJwYvs21rzUcb6fAvd3orj2KgtkjOxHyi2cwKBgBOD
+E/YjpzWjxGADqFlHfcN++Kj01Gj8VucNV6gTr3Kfz1kkDLv8zfGiP7hAfOnBTpJ
iWk0rUZRCadLdkDpmsONNJxG+oUnhOvuxgxBxNrrSjpjiHtJUmXpdahNhKFvjIP5
thLkbD70rT75+h15c/6G3NawiD1WtkgL//aNyuTLAoGAOICo2RQdrY15al9k9Yfi
R4YWKNlIOkSB250AvRJRqWil2np55+woHScxm8MI6xaoEe7jwSL5yCNLQUKOq9V5
MsH6dL1mgh10RZvYE5SDs8+QIpMmNtTbBCT+JSpOr+oB1DYHmgZG97Lf6xJfhGZP
nHFpqK//mn6ADPOkaZKL7aE=
-----END PRIVATE KEY-----`;

const SPKI_PUB_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3NUKZi3mvI9/soliuUSl
69QhyBcUPMNEresgRWk3lTbz7MwOaOqFJkVyn7eu9Jp5owIAcfZ8uA8uGrWNLws6
EzGYOEYd6rUgaOBDw1ipWtjtPPE4K0GkYOT1HNSqiD1oHbe640BZgHYJyIDbrrMy
0POHN6WN90u7QDcHvSIyY6wWfSvGjf//VG4BawA95Z27MFgCcFL92r2ODiIlq3Cl
XGASt6J14S6mPoyV7QXQEc38zPxBrBRJgsXfsmgoC4I1r7oBH8+O5C+hcRog6Pzl
NRhkFUVXvY7v96LEmj6n350LfE7WWJQVjzubdHJQpIxXrdjIjktLJgxMDgOvMcmo
KQIDAQAB
-----END PUBLIC KEY-----`;

function spkiToBytes(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN[^-]+-----/g, "")
    .replace(/-----END[^-]+-----/g, "")
    .replace(/\s+/g, "");
  return _internal.base64ToBytes(b64);
}

Deno.test("sha256Base64 of empty payload matches the well-known digest", async () => {
  const digest = await _internal.sha256Base64(new Uint8Array());
  assertEquals(digest, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
});

Deno.test("base64 round-trips arbitrary bytes", () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 255, 128, 64]);
  const round = _internal.base64ToBytes(_internal.bytesToBase64(bytes));
  assertEquals(Array.from(round), Array.from(bytes));
});

Deno.test("derLength encodes short and long forms", () => {
  assertEquals(_internal.derLength(0), [0x00]);
  assertEquals(_internal.derLength(127), [0x7f]);
  assertEquals(_internal.derLength(128), [0x81, 0x80]);
  assertEquals(_internal.derLength(256), [0x82, 0x01, 0x00]);
  assertEquals(_internal.derLength(1234), [0x82, 0x04, 0xd2]);
});

Deno.test("iaasHost builds region host and honors override", () => {
  const base = {
    tenancyId: "t",
    userId: "u",
    fingerprint: "f",
    privateKey: "k",
    region: "us-ashburn-1",
    instanceId: "i",
  };
  assertEquals(_internal.iaasHost(base), "iaas.us-ashburn-1.oraclecloud.com");
  assertEquals(
    _internal.iaasHost({ ...base, endpoint: "iaas.example.gov" }),
    "iaas.example.gov",
  );
});

Deno.test("PKCS#1 and PKCS#8 PEM parse to identical DER", () => {
  const fromPkcs1 = _internal.pemToPkcs8Der(PKCS1_PEM);
  const fromPkcs8 = _internal.pemToPkcs8Der(PKCS8_PEM);
  assertEquals(Array.from(fromPkcs1), Array.from(fromPkcs8));
});

Deno.test("rejects an encrypted PEM key", () => {
  let threw = false;
  try {
    _internal.pemToPkcs8Der(
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc\n-----END ENCRYPTED PRIVATE KEY-----",
    );
  } catch {
    threw = true;
  }
  assert(threw, "expected encrypted key to be rejected");
});

// ---------------------------------------------------------------------------
// Method-level tests with a mocked fetch (exercise the full signed-request path)
// ---------------------------------------------------------------------------

const TEST_GLOBAL_ARGS = {
  tenancyId: "ocid1.tenancy.oc1..aaaatenancy",
  userId: "ocid1.user.oc1..aaaauser",
  fingerprint: "12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef",
  privateKey: PKCS1_PEM,
  region: "us-ashburn-1",
  instanceId: "ocid1.instance.oc1..aaaainstance",
};

// deno-lint-ignore no-explicit-any
type AnyCtx = any;

function makeContext(): {
  ctx: AnyCtx;
  writes: Array<{ spec: string; name: string; data: Record<string, unknown> }>;
} {
  const writes: Array<
    { spec: string; name: string; data: Record<string, unknown> }
  > = [];
  const ctx = {
    globalArgs: TEST_GLOBAL_ARGS,
    logger: { info: () => {}, warn: () => {} },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };
  return { ctx, writes };
}

async function withMockedFetch<T>(
  handler: (url: string, init: RequestInit) => Response,
  fn: () => Promise<T>,
): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) =>
    Promise.resolve(
      handler(String(input), init ?? {}),
    )) as typeof globalThis.fetch;
  try {
    return await fn();
  } finally {
    globalThis.fetch = original;
  }
}

Deno.test("reboot issues a signed InstanceAction and records the result", async () => {
  const { ctx, writes } = makeContext();
  let captured: { url: string; init: RequestInit } | null = null;

  await withMockedFetch(
    (url, init) => {
      captured = { url, init };
      return new Response(
        JSON.stringify({
          id: TEST_GLOBAL_ARGS.instanceId,
          lifecycleState: "STARTING",
          displayName: "web-1",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
    () => model.methods.reboot.execute({ action: "SOFTRESET" }, ctx),
  );

  assert(captured !== null, "fetch should have been called");
  const call = captured as { url: string; init: RequestInit };
  assertEquals(call.init.method, "POST");
  assertStringIncludes(
    call.url,
    "https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances/",
  );
  assertStringIncludes(call.url, "action=SOFTRESET");

  const headers = call.init.headers as Record<string, string>;
  assertStringIncludes(headers["authorization"], 'Signature version="1"');
  assertStringIncludes(headers["authorization"], "algorithm=\"rsa-sha256\"");
  assert(headers["x-date"], "x-date header must be signed and sent");
  assert(headers["x-content-sha256"], "x-content-sha256 must be present");

  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "action");
  assertEquals(writes[0].data.action, "SOFTRESET");
  assertEquals(writes[0].data.lifecycleState, "STARTING");
});

Deno.test("reboot with RESET puts the hard action in the query and record", async () => {
  const { ctx, writes } = makeContext();
  let url = "";
  await withMockedFetch(
    (u) => {
      url = u;
      return new Response(JSON.stringify({ lifecycleState: "STOPPING" }), {
        status: 200,
      });
    },
    () => model.methods.reboot.execute({ action: "RESET" }, ctx),
  );
  assertStringIncludes(url, "action=RESET");
  assertEquals(writes[0].data.action, "RESET");
});

Deno.test("sync fetches instance state via GET and maps the resource", async () => {
  const { ctx, writes } = makeContext();
  let method = "";
  await withMockedFetch(
    (_u, init) => {
      method = String(init.method ?? "GET");
      return new Response(
        JSON.stringify({
          id: TEST_GLOBAL_ARGS.instanceId,
          lifecycleState: "RUNNING",
          displayName: "web-1",
          shape: "VM.Standard.E4.Flex",
          region: "us-ashburn-1",
        }),
        { status: 200 },
      );
    },
    () => model.methods.sync.execute({}, ctx),
  );
  assertEquals(method, "GET");
  assertEquals(writes[0].spec, "instance");
  assertEquals(writes[0].data.lifecycleState, "RUNNING");
  assertEquals(writes[0].data.shape, "VM.Standard.E4.Flex");
});

Deno.test("a non-2xx OCI response throws and writes nothing", async () => {
  const { ctx, writes } = makeContext();
  let threw = false;
  await withMockedFetch(
    () => new Response("InstanceNotFound", { status: 404 }),
    async () => {
      try {
        await model.methods.reboot.execute({ action: "SOFTRESET" }, ctx);
      } catch (e) {
        threw = true;
        assertStringIncludes((e as Error).message, "404");
      }
    },
  );
  assert(threw, "expected a 404 to throw");
  assertEquals(writes.length, 0, "must not write a resource on failure");
});

Deno.test("signature from an imported PKCS#1 key verifies against the public key", async () => {
  const key = await _internal.importSigningKey(PKCS1_PEM);
  const message = new TextEncoder().encode(
    "(request-target): post /20160918/instances/ocid1.instance..x?action=SOFTRESET",
  );
  const sig = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    message,
  );

  const pubKey = await crypto.subtle.importKey(
    "spki",
    spkiToBytes(SPKI_PUB_PEM).buffer as ArrayBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    pubKey,
    sig,
    message,
  );
  assert(ok, "signature produced by importSigningKey must verify");
});
