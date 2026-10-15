// Pruebas del cliente de Apple. Se ejecutan con:  deno test supabase/functions/_shared/apple_client_test.ts
// No usan la red ni claves reales: la clave se genera aquí y las respuestas de Apple son simuladas.
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  AppleApiClient,
  AppleApiError,
  pemToDer,
  signAppleToken,
} from "./apple_client.ts";
import {
  SupabaseSignedDataVerifier,
  shouldTryOtherEnvironment,
  shouldTrySandboxVerifier,
} from "./apple.ts";
import {
  Environment,
  VerificationException,
  VerificationStatus,
} from "npm:@apple/app-store-server-library@3.1.0";
import {
  TEST_NOTIFICATION,
  TEST_NOTIFICATION_LEAF_WITHOUT_APPLE_MARK,
  TEST_ROOT,
  TEST_TRANSACTION,
} from "./apple_jws_fixtures.ts";

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function makeKeyPair() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const der = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", pair.privateKey),
  );
  let binary = "";
  for (const b of der) binary += String.fromCharCode(b);
  const body = btoa(binary)
    .match(/.{1,64}/g)!
    .join("\n");
  return {
    pair,
    pem: `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`,
  };
}

const creds = (privateKey: string) => ({
  privateKey,
  keyId: "ABC123DEFG",
  issuerId: "69a6de7e-0000-0000-0000-5b8c86461234",
  bundleId: "com.netglobal.teneo",
});

Deno.test(
  "pemToDer acepta la clave con líneas BEGIN/END, sin ellas y con \\n escritos como texto",
  async () => {
    const { pem } = await makeKeyPair();
    const a = pemToDer(pem);
    const b = pemToDer(pem.replace(/-----[A-Z ]+-----/g, ""));
    const c = pemToDer(pem.trim().replace(/\n/g, "\\n"));
    assert(a.length > 60);
    assertEquals(a, b);
    assertEquals(a, c);
  },
);

Deno.test(
  "la credencial es un JWT ES256 con los datos de Apple y su firma es válida",
  async () => {
    const { pair, pem } = await makeKeyPair();
    const token = await signAppleToken(creds(pem), 1_700_000_000);
    const [h, p, s] = token.split(".");
    const header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(h)));
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(p)));
    assertEquals(header, { alg: "ES256", kid: "ABC123DEFG", typ: "JWT" });
    assertEquals(payload, {
      iss: "69a6de7e-0000-0000-0000-5b8c86461234",
      iat: 1_700_000_000,
      exp: 1_700_000_300,
      aud: "appstoreconnect-v1",
      bid: "com.netglobal.teneo",
    });
    const signature = base64UrlToBytes(s);
    assertEquals(signature.length, 64); // r || s, el formato de un JWT
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pair.publicKey,
      signature,
      new TextEncoder().encode(`${h}.${p}`),
    );
    assert(ok, "la firma debe verificarse con la clave pública");
  },
);

Deno.test(
  "una clave que no es P-256 se rechaza en vez de firmar mal",
  async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-384" },
      true,
      ["sign", "verify"],
    );
    const der = new Uint8Array(
      await crypto.subtle.exportKey("pkcs8", pair.privateKey),
    );
    let binary = "";
    for (const b of der) binary += String.fromCharCode(b);
    await assertRejects(() =>
      signAppleToken(
        creds(
          `-----BEGIN PRIVATE KEY-----\n${btoa(binary)}\n-----END PRIVATE KEY-----`,
        ),
      ),
    );
  },
);

Deno.test(
  "pide la transacción al servidor de Apple del entorno correcto, con la credencial",
  async () => {
    const { pem } = await makeKeyPair();
    const seen: { url: string; auth: string | null }[] = [];
    const fakeFetch = ((url: string | URL | Request, init?: RequestInit) => {
      seen.push({
        url: String(url),
        auth: new Headers(init?.headers).get("Authorization"),
      });
      return Promise.resolve(
        new Response(
          JSON.stringify({ signedTransactionInfo: "jws.de.prueba" }),
          { status: 200 },
        ),
      );
    }) as typeof fetch;

    const sandbox = new AppleApiClient(creds(pem), "sandbox", fakeFetch);
    const prod = new AppleApiClient(creds(pem), "production", fakeFetch);
    assertEquals(
      (await sandbox.getTransactionInfo("1000000000000001"))
        .signedTransactionInfo,
      "jws.de.prueba",
    );
    await prod.getAllSubscriptionStatuses("1000000000000001");

    assertEquals(
      seen[0].url,
      "https://api.storekit-sandbox.itunes.apple.com/inApps/v1/transactions/1000000000000001",
    );
    assertEquals(
      seen[1].url,
      "https://api.storekit.itunes.apple.com/inApps/v1/subscriptions/1000000000000001",
    );
    assert(seen[0].auth?.startsWith("Bearer ey"));
  },
);

Deno.test(
  "un 404 de Apple se informa como AppleApiError con su código, para poder probar el otro entorno",
  async () => {
    const { pem } = await makeKeyPair();
    const fakeFetch = (() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            errorCode: 4040010,
            errorMessage: "Transaction id not found.",
          }),
          { status: 404 },
        ),
      )) as typeof fetch;
    const client = new AppleApiClient(creds(pem), "production", fakeFetch);
    const error = await assertRejects(
      () => client.getTransactionInfo("1"),
      AppleApiError,
    );
    assertEquals(error.httpStatus, 404);
    assertEquals(error.errorCode, 4040010);
  },
);

Deno.test(
  "un 401 (credenciales rechazadas) y una respuesta que no es JSON también se informan",
  async () => {
    const { pem } = await makeKeyPair();
    const fakeFetch = (() =>
      Promise.resolve(
        new Response("no autorizado", { status: 401 }),
      )) as typeof fetch;
    const client = new AppleApiClient(creds(pem), "sandbox", fakeFetch);
    const error = await assertRejects(
      () => client.getTransactionInfo("1"),
      AppleApiError,
    );
    assertEquals(error.httpStatus, 401);
    assertEquals(error.errorCode, null);
  },
);

Deno.test(
  "se prueba el otro entorno con 404 y con 401 (producción rechaza mientras la app no esté publicada), no con otros errores",
  () => {
    assertEquals(
      shouldTryOtherEnvironment(new AppleApiError(404, 4040010, null)),
      true,
    );
    assertEquals(
      shouldTryOtherEnvironment(new AppleApiError(401, null, null)),
      true,
    );
    assertEquals(
      shouldTryOtherEnvironment(new AppleApiError(500, null, null)),
      false,
    );
    assertEquals(
      shouldTryOtherEnvironment(new AppleApiError(429, null, null)),
      false,
    );
    assertEquals(shouldTryOtherEnvironment(new Error("otro")), false);
  },
);

Deno.test(
  "un aviso rechazado por el verificador de producción por entorno o por identificador de app se prueba como sandbox",
  () => {
    assertEquals(
      shouldTrySandboxVerifier(
        new VerificationException(VerificationStatus.INVALID_ENVIRONMENT),
      ),
      true,
    );
    assertEquals(
      shouldTrySandboxVerifier(
        new VerificationException(VerificationStatus.INVALID_APP_IDENTIFIER),
      ),
      true,
    );
    // una firma inválida o un certificado inválido NO se reintenta: es un aviso falso
    assertEquals(
      shouldTrySandboxVerifier(
        new VerificationException(VerificationStatus.VERIFICATION_FAILURE),
      ),
      false,
    );
    assertEquals(
      shouldTrySandboxVerifier(
        new VerificationException(VerificationStatus.INVALID_CERTIFICATE),
      ),
      false,
    );
    assertEquals(shouldTrySandboxVerifier(new Error("otro")), false);
  },
);

// --- El verificador de la biblioteca de Apple, con la verificación de certificados reemplazada (SupabaseSignedDataVerifier) ---
const BUNDLE = "com.netglobal.teneo";
const verifierIn = (env: Environment, bundle = BUNDLE) =>
  new SupabaseSignedDataVerifier([TEST_ROOT], env, bundle, 123456789);

async function statusOf(
  promise: Promise<unknown>,
): Promise<VerificationStatus> {
  const error = await assertRejects(() => promise, VerificationException);
  return error.status;
}

Deno.test(
  "el verificador con el reemplazo decodifica un aviso y una transacción de sandbox bien firmados",
  async () => {
    const verifier = verifierIn(Environment.SANDBOX);
    const notification =
      await verifier.verifyAndDecodeNotification(TEST_NOTIFICATION);
    assertEquals(String(notification.notificationType), "TEST");
    assertEquals(
      notification.notificationUUID,
      "11111111-2222-3333-4444-555555555555",
    );
    const transaction =
      await verifier.verifyAndDecodeTransaction(TEST_TRANSACTION);
    assertEquals(transaction.productId, "teneo.pro.monthly");
  },
);

Deno.test(
  "un aviso de sandbox lo rechaza el verificador de producción de forma que se reintenta como sandbox",
  async () => {
    const status = await statusOf(
      verifierIn(Environment.PRODUCTION).verifyAndDecodeNotification(
        TEST_NOTIFICATION,
      ),
    );
    assert(
      shouldTrySandboxVerifier(new VerificationException(status)),
      `un aviso de sandbox debe poder reintentarse como sandbox (estado ${status})`,
    );
  },
);

Deno.test("el verificador sigue exigiendo el bundle ID de la app", async () => {
  assertEquals(
    await statusOf(
      verifierIn(
        Environment.SANDBOX,
        "com.otra.app",
      ).verifyAndDecodeNotification(TEST_NOTIFICATION),
    ),
    VerificationStatus.INVALID_APP_IDENTIFIER,
  );
});

Deno.test(
  "el verificador rechaza un aviso sin la marca de Apple, con la raíz equivocada o alterado",
  async () => {
    const sandbox = verifierIn(Environment.SANDBOX);
    assertEquals(
      await statusOf(
        sandbox.verifyAndDecodeNotification(
          TEST_NOTIFICATION_LEAF_WITHOUT_APPLE_MARK,
        ),
      ),
      VerificationStatus.VERIFICATION_FAILURE,
    );
    const otherRoot = new SupabaseSignedDataVerifier(
      [],
      Environment.SANDBOX,
      BUNDLE,
      123456789,
    );
    assertEquals(
      await statusOf(otherRoot.verifyAndDecodeNotification(TEST_NOTIFICATION)),
      VerificationStatus.VERIFICATION_FAILURE,
    );
    const [h, , s] = TEST_NOTIFICATION.split(".");
    const forgedPayload = btoa(
      JSON.stringify({
        notificationType: "REFUND",
        notificationUUID: "x",
        data: { environment: "Sandbox", bundleId: BUNDLE },
      }),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    assertEquals(
      await statusOf(
        sandbox.verifyAndDecodeNotification(`${h}.${forgedPayload}.${s}`),
      ),
      VerificationStatus.VERIFICATION_FAILURE,
    );
  },
);
