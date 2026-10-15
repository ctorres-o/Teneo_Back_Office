// Lado Apple de las suscripciones: pide a la App Store Server API el estado REAL de una compra y verifica las
// firmas de Apple (cadena de certificados hasta la raíz de Apple) con la biblioteca oficial.
//
// Secretos (Supabase > Edge Functions > Secrets), nunca en el código:
//   APPLE_IAP_PRIVATE_KEY  contenido del .p8 de App Store Connect (Users and Access > Integrations > In-App Purchase)
//   APPLE_IAP_KEY_ID       Key ID de esa clave
//   APPLE_IAP_ISSUER_ID    Issuer ID
//   APPLE_BUNDLE_ID        com.netglobal.teneo
//   APPLE_APP_ID           Apple ID numérico de la app (obligatorio para verificar en producción)
//
// Regla de fondo (MATRIZ_DE_PLANES.md, principio 2): el estado y la fecha de término salen de Apple, nunca de la app.
import {
  AutoRenewStatus,
  Environment,
  SignedDataVerifier,
  Status,
  VerificationException,
  VerificationStatus,
} from "npm:@apple/app-store-server-library@3.1.0";
import { Buffer } from "node:buffer";
import { APPLE_ROOT_CAS_BASE64 } from "./apple_roots.ts";
import { AppleApiClient, AppleApiError } from "./apple_client.ts";

export type AppleEnv = "production" | "sandbox";

/** Falta uno o más secretos: se nombra cuáles para poder arreglarlo sin adivinar. */
export class AppleConfigError extends Error {}
/** Apple no conoce esa transacción (ni en producción ni en sandbox). */
export class AppleNotFoundError extends Error {}

interface AppleConfig {
  privateKey: string;
  keyId: string;
  issuerId: string;
  bundleId: string;
  appId: number;
}

function config(): AppleConfig {
  const names = [
    "APPLE_IAP_PRIVATE_KEY",
    "APPLE_IAP_KEY_ID",
    "APPLE_IAP_ISSUER_ID",
    "APPLE_BUNDLE_ID",
    "APPLE_APP_ID",
  ];
  const missing = names.filter((n) => !Deno.env.get(n)?.trim());
  if (missing.length > 0) {
    throw new AppleConfigError(
      `Faltan secretos de Apple en Supabase: ${missing.join(", ")}`,
    );
  }
  const appId = Number(Deno.env.get("APPLE_APP_ID")!.trim());
  if (!Number.isInteger(appId) || appId <= 0) {
    throw new AppleConfigError(
      "APPLE_APP_ID debe ser el Apple ID numérico de la app.",
    );
  }
  return {
    // Si el .p8 se pegó con "\n" escritos como texto en vez de saltos de línea, se corrige.
    privateKey: Deno.env
      .get("APPLE_IAP_PRIVATE_KEY")!
      .trim()
      .replace(/\\n/g, "\n"),
    keyId: Deno.env.get("APPLE_IAP_KEY_ID")!.trim(),
    issuerId: Deno.env.get("APPLE_IAP_ISSUER_ID")!.trim(),
    bundleId: Deno.env.get("APPLE_BUNDLE_ID")!.trim(),
    appId,
  };
}

function appleEnvironment(env: AppleEnv): Environment {
  return env === "production" ? Environment.PRODUCTION : Environment.SANDBOX;
}

// El cliente de la biblioteca de Apple firma con `jsonwebtoken` y falla en las Edge Functions (ver apple_client.ts): se usa el propio.
function clientFor(env: AppleEnv): AppleApiClient {
  const c = config();
  return new AppleApiClient(
    {
      privateKey: c.privateKey,
      keyId: c.keyId,
      issuerId: c.issuerId,
      bundleId: c.bundleId,
    },
    env,
  );
}

export function verifierFor(env: AppleEnv): SignedDataVerifier {
  const c = config();
  const roots = APPLE_ROOT_CAS_BASE64.map((b64) => Buffer.from(b64, "base64"));
  return new SignedDataVerifier(
    roots,
    true,
    appleEnvironment(env),
    c.bundleId,
    c.appId,
  );
}

/** "Sandbox" / "Production" (texto de Apple) -> nuestro valor. Cualquier otro (Xcode, LocalTesting) se trata como sandbox. */
export function envFromApple(value: string | undefined): AppleEnv {
  return value === "Production" ? "production" : "sandbox";
}

export interface AppleSubscriptionState {
  environment: AppleEnv;
  originalTransactionId: string;
  transactionId: string;
  productId: string;
  purchaseDate: Date | null;
  expiresDate: Date | null;
  /** active | past_due (reintento de cobro o gracia: sin gracia, no vale) | expired (vencida o reembolsada) */
  status: "active" | "past_due" | "expired";
  autoRenew: boolean;
  revoked: boolean;
  /** Precio en la moneda de la tienda (Apple lo entrega en milésimas). */
  price: number | null;
  currency: string | null;
}

async function stateIn(
  env: AppleEnv,
  transactionId: string,
): Promise<AppleSubscriptionState> {
  const client = clientFor(env);
  const verifier = verifierFor(env);

  // 1) Con cualquier transacción de la compra se obtiene la transacción original.
  const info = await client.getTransactionInfo(transactionId);
  if (!info.signedTransactionInfo)
    throw new AppleNotFoundError("Apple no devolvió la transacción.");
  const given = await verifier.verifyAndDecodeTransaction(
    info.signedTransactionInfo,
  );
  const originalId = given.originalTransactionId ?? given.transactionId;
  if (!originalId)
    throw new AppleNotFoundError(
      "La transacción de Apple no trae identificador.",
    );

  // 2) Estado actual de la suscripción (el último movimiento, no el que mandó la app).
  const statuses = await client.getAllSubscriptionStatuses(originalId);
  const items = (statuses.data ?? []).flatMap((g) => g.lastTransactions ?? []);
  const item = items.find((i) => i.originalTransactionId === originalId);
  if (!item?.signedTransactionInfo)
    throw new AppleNotFoundError(
      "Apple no encontró el estado de esa suscripción.",
    );

  const tx = await verifier.verifyAndDecodeTransaction(
    item.signedTransactionInfo,
  );
  const renewal = item.signedRenewalInfo
    ? await verifier.verifyAndDecodeRenewalInfo(item.signedRenewalInfo)
    : undefined;
  if (!tx.productId || !tx.originalTransactionId || !tx.transactionId) {
    throw new AppleNotFoundError("La transacción de Apple está incompleta.");
  }

  const revoked = tx.revocationDate != null || item.status === Status.REVOKED;
  let status: AppleSubscriptionState["status"];
  if (revoked) status = "expired";
  else if (item.status === Status.ACTIVE) status = "active";
  else if (
    item.status === Status.BILLING_RETRY ||
    item.status === Status.BILLING_GRACE_PERIOD
  )
    status = "past_due";
  else status = "expired";

  return {
    environment: env,
    originalTransactionId: tx.originalTransactionId,
    transactionId: tx.transactionId,
    productId: tx.productId,
    purchaseDate: tx.originalPurchaseDate
      ? new Date(tx.originalPurchaseDate)
      : null,
    expiresDate: tx.expiresDate ? new Date(tx.expiresDate) : null,
    status,
    autoRenew: renewal?.autoRenewStatus === AutoRenewStatus.ON,
    revoked,
    price: tx.price != null ? tx.price / 1000 : null,
    currency: tx.currency ?? null,
  };
}

/** Estado actual de una compra de Apple. Prueba producción y, si Apple no la conoce, sandbox (TestFlight y cuentas de prueba). */
export async function fetchSubscriptionState(
  transactionId: string,
): Promise<AppleSubscriptionState> {
  for (const env of ["production", "sandbox"] as AppleEnv[]) {
    try {
      return await stateIn(env, transactionId);
    } catch (e) {
      // 404 = esa transacción no existe en este entorno: se prueba el siguiente.
      if (e instanceof AppleApiError && e.httpStatus === 404) continue;
      throw e;
    }
  }
  throw new AppleNotFoundError("Apple no reconoce esa compra.");
}

export interface DecodedNotification {
  environment: AppleEnv;
  notificationUUID: string;
  notificationType: string;
  subtype: string | null;
  /** Transacción incluida en el aviso, ya verificada (los avisos de prueba no la traen). */
  transactionId: string | null;
}

/** Verifica la firma de un aviso de Apple y lo decodifica. Prueba producción y, si el aviso es de sandbox, sandbox. */
export async function decodeNotification(
  signedPayload: string,
): Promise<DecodedNotification> {
  let env: AppleEnv = "production";
  let payload;
  try {
    payload =
      await verifierFor("production").verifyAndDecodeNotification(
        signedPayload,
      );
  } catch (e) {
    if (
      e instanceof VerificationException &&
      e.status === VerificationStatus.INVALID_ENVIRONMENT
    ) {
      env = "sandbox";
      payload =
        await verifierFor("sandbox").verifyAndDecodeNotification(signedPayload);
    } else {
      throw e;
    }
  }
  let transactionId: string | null = null;
  const signedTx = payload.data?.signedTransactionInfo;
  if (signedTx) {
    const tx = await verifierFor(env).verifyAndDecodeTransaction(signedTx);
    transactionId = tx.transactionId ?? null;
  }
  return {
    environment: env,
    notificationUUID: payload.notificationUUID ?? "",
    notificationType: String(payload.notificationType ?? ""),
    subtype: payload.subtype ? String(payload.subtype) : null,
    transactionId,
  };
}

/** Texto corto y sin datos sensibles para registrar o devolver un error de Apple. */
export function describeAppleError(e: unknown): string {
  if (e instanceof AppleApiError) return e.message;
  if (e instanceof VerificationException)
    return `La firma de Apple no se pudo verificar (código ${e.status})`;
  return e instanceof Error ? e.message : String(e);
}
