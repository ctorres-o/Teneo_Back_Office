// Comprobación manual de las credenciales de Apple (App Store Server API), sin hacer una compra.
// Se ejecuta en TU computador: la clave .p8 se lee del disco y NUNCA se imprime ni se envía a otro lugar que no sea Apple.
//
// Uso (el Key ID y el Issuer ID no son secretos; son los que aparecen en App Store Connect > Users and Access > Integrations > In-App Purchase):
//   APPLE_KEY_PATH=~/Downloads/SubscriptionKey_XXXX.p8 APPLE_KEY_ID=XXXX APPLE_ISSUER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
//     deno run --allow-read --allow-net --allow-env scripts/apple-selftest.ts
//
// Qué hace: firma la credencial igual que las funciones del servidor y le pide a Apple que envíe un AVISO DE PRUEBA a la URL de avisos
// configurada en App Store Connect (apple-notifications), primero en sandbox y luego en producción. Después consulta si Apple pudo entregarlo.
//   200 de Apple = la credencial es válida.   401 = Apple rechaza la credencial (Key ID, Issuer ID, tipo de clave o clave mal puestos).
import { signAppleToken } from "../supabase/functions/_shared/apple_client.ts";

const HOSTS = {
  sandbox: "https://api.storekit-sandbox.itunes.apple.com",
  production: "https://api.storekit.itunes.apple.com",
} as const;

const keyPath = Deno.env
  .get("APPLE_KEY_PATH")
  ?.replace(/^~/, Deno.env.get("HOME") ?? "~");
const keyId = Deno.env.get("APPLE_KEY_ID")?.trim();
const issuerId = Deno.env.get("APPLE_ISSUER_ID")?.trim();
const bundleId =
  Deno.env.get("APPLE_BUNDLE_ID")?.trim() || "com.netglobal.teneo";

if (!keyPath || !keyId || !issuerId) {
  console.error(
    "Faltan datos. Define APPLE_KEY_PATH, APPLE_KEY_ID y APPLE_ISSUER_ID (ver el uso al inicio de este archivo).",
  );
  Deno.exit(1);
}

const fileName = keyPath.split("/").pop() ?? "";
console.log(`Archivo: ${fileName}`);
if (!fileName.includes(keyId)) {
  console.log(
    `  ATENCIÓN: el nombre del archivo no contiene el Key ID "${keyId}". Si el ID del nombre es otro, ese es el Key ID correcto.`,
  );
}
if (fileName.startsWith("AuthKey_")) {
  console.log(
    "  ATENCIÓN: un archivo AuthKey_ es la clave de la API de App Store Connect, NO la de In-App Purchase (SubscriptionKey_).",
  );
}

const privateKey = await Deno.readTextFile(keyPath);
const creds = { privateKey, keyId, issuerId, bundleId };

function describe(status: number): string {
  if (status === 200) return "OK: Apple aceptó la credencial.";
  if (status === 401) {
    return "Apple RECHAZA la credencial (401). Revisa: que el Key ID sea el del nombre del archivo, que el Issuer ID sea el de la pantalla de claves de In-App Purchase, y que el .p8 sea de ESA clave.";
  }
  if (status === 404) return "Apple no encontró el recurso (404).";
  if (status === 429)
    return "Demasiadas solicitudes (429). Espera un rato y vuelve a intentar.";
  return `Apple respondió ${status}.`;
}

async function call(
  env: keyof typeof HOSTS,
  method: string,
  path: string,
): Promise<{ status: number; body: string }> {
  const token = await signAppleToken(creds);
  const res = await fetch(`${HOSTS[env]}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  return { status: res.status, body: await res.text() };
}

for (const env of ["sandbox", "production"] as const) {
  console.log(`\n== ${env} ==`);
  const sent = await call(env, "POST", "/inApps/v1/notifications/test");
  console.log(describe(sent.status));
  if (sent.status !== 200) {
    if (sent.body)
      console.log(`  Respuesta de Apple: ${sent.body.slice(0, 300)}`);
    continue;
  }
  let testToken: string | undefined;
  try {
    testToken = JSON.parse(sent.body).testNotificationToken;
  } catch {
    // sin token: no se puede consultar la entrega
  }
  if (!testToken) continue;
  console.log(
    "  Apple enviará el aviso de prueba. Consultando la entrega en 6 segundos…",
  );
  await new Promise((r) => setTimeout(r, 6000));
  const status = await call(
    env,
    "GET",
    `/inApps/v1/notifications/test/${encodeURIComponent(testToken)}`,
  );
  console.log(`  Consulta de entrega: HTTP ${status.status}`);
  try {
    const parsed = JSON.parse(status.body);
    const attempts = parsed.sendAttempts ?? [];
    console.log(
      `  Resultado final: ${parsed.firstSendAttemptResult ?? "(sin dato todavía)"}  | intentos: ${attempts.length}`,
    );
    for (const a of attempts)
      console.log(`    - ${a.attemptDate ?? ""}: ${a.sendAttemptResult}`);
  } catch {
    console.log(`  ${status.body.slice(0, 300)}`);
  }
}
console.log(
  "\nListo. Si el resultado final dice SUCCESS, el aviso llegó a apple-notifications y se verificó bien.",
);
