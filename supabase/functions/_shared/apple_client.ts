// Cliente mínimo de la App Store Server API, escrito con las herramientas nativas de Deno (WebCrypto y fetch).
//
// POR QUÉ NO SE USA EL CLIENTE DE LA BIBLIOTECA DE APPLE: firma la credencial con `jsonwebtoken`, pensado para Node. En las Edge
// Functions de Supabase fallaba antes de hablar con Apple con: "alg" parameter "ES256" requires curve "prime256v1" (el entorno
// no informa el nombre de la curva como Node lo espera). Aquí la clave se importa con WebCrypto, que no tiene ese problema.
//
// Solo cubre lo que necesitamos: pedir una transacción y el estado de una suscripción. La verificación de las firmas de lo que
// Apple responde sigue haciéndola la biblioteca oficial (SignedDataVerifier), en `apple.ts`.

export type AppleEnvironment = "production" | "sandbox";

export interface AppleApiCredentials {
  /** Contenido del .p8 de App Store Connect (clave de "In-App Purchase"), con o sin las líneas BEGIN/END. */
  privateKey: string;
  keyId: string;
  issuerId: string;
  bundleId: string;
}

/** Apple respondió con un error HTTP (404 = la transacción no existe en ese entorno; 401 = credenciales rechazadas). */
export class AppleApiError extends Error {
  constructor(
    readonly httpStatus: number,
    readonly errorCode: number | null,
    readonly appleMessage: string | null,
  ) {
    super(`Apple respondió ${httpStatus}${errorCode ? ` (${errorCode})` : ""}`);
    this.name = "AppleApiError";
  }
}

const HOSTS: Record<AppleEnvironment, string> = {
  production: "https://api.storekit.itunes.apple.com",
  sandbox: "https://api.storekit-sandbox.itunes.apple.com",
};

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function textToBase64Url(text: string): string {
  return base64UrlEncode(new TextEncoder().encode(text));
}

/** PEM (PKCS#8) -> bytes. Acepta la clave con o sin las líneas BEGIN/END y con "\n" escritos como texto. */
export function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const body = pem
    .replace(/\\n/g, "\n")
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(body);
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Credencial (JWT ES256) que Apple exige en cada llamada. Vale 5 minutos. */
export async function signAppleToken(
  creds: AppleApiCredentials,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(creds.privateKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const header = { alg: "ES256", kid: creds.keyId, typ: "JWT" };
  const payload = {
    iss: creds.issuerId,
    iat: nowSeconds,
    exp: nowSeconds + 300,
    aud: "appstoreconnect-v1",
    bid: creds.bundleId,
  };
  const signingInput = `${textToBase64Url(JSON.stringify(header))}.${textToBase64Url(JSON.stringify(payload))}`;
  // WebCrypto entrega la firma ECDSA ya en el formato que pide un JWT (r || s, 64 bytes).
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      new TextEncoder().encode(signingInput),
    ),
  );
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export interface AppleTransactionResponse {
  signedTransactionInfo?: string;
}

export interface AppleStatusLastTransaction {
  status?: number;
  originalTransactionId?: string;
  signedTransactionInfo?: string;
  signedRenewalInfo?: string;
}

export interface AppleStatusResponse {
  data?: {
    subscriptionGroupIdentifier?: string;
    lastTransactions?: AppleStatusLastTransaction[];
  }[];
}

export class AppleApiClient {
  constructor(
    private readonly creds: AppleApiCredentials,
    private readonly environment: AppleEnvironment,
    // Se puede reemplazar en las pruebas.
    private readonly fetchFn: typeof fetch = fetch,
  ) {}

  private async get<T>(path: string): Promise<T> {
    const token = await signAppleToken(this.creds);
    const res = await this.fetchFn(`${HOSTS[this.environment]}${path}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
    });
    if (!res.ok) {
      let code: number | null = null;
      let message: string | null = null;
      try {
        const body = await res.json();
        code = typeof body?.errorCode === "number" ? body.errorCode : null;
        message =
          typeof body?.errorMessage === "string" ? body.errorMessage : null;
      } catch {
        // El cuerpo no era JSON: solo importa el código HTTP.
      }
      throw new AppleApiError(res.status, code, message);
    }
    return (await res.json()) as T;
  }

  /** Una transacción (cualquiera de la compra). */
  getTransactionInfo(transactionId: string): Promise<AppleTransactionResponse> {
    return this.get(
      `/inApps/v1/transactions/${encodeURIComponent(transactionId)}`,
    );
  }

  /** Estado actual de las suscripciones de la compra. */
  getAllSubscriptionStatuses(
    transactionId: string,
  ): Promise<AppleStatusResponse> {
    return this.get(
      `/inApps/v1/subscriptions/${encodeURIComponent(transactionId)}`,
    );
  }
}
