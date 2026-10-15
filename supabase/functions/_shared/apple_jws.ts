// Verificación de las firmas (JWS) de Apple: transacciones, renovaciones y avisos.
//
// POR QUÉ EXISTE: la biblioteca oficial de Apple verifica con el `X509Certificate` de Node. El de las Edge Functions de Supabase
// (edge-runtime compatible con Deno 2.1.4) está incompleto: falla con "Not implemented: crypto.X509Certificate.prototype.toString",
// luego `.raw`, y así. Aquí la misma verificación se hace con `jsrsasign` (puro JavaScript, la misma pieza que usa la biblioteca) y
// WebCrypto, sin `node:crypto`.
//
// QUÉ COMPRUEBA (lo mismo que la biblioteca, salvo la revocación):
//   1. La cadena del encabezado `x5c` (hoja, intermedio, raíz) tiene 3 certificados y el intermedio está firmado por una de las
//      raíces de Apple que TENEMOS FIJADAS (la raíz del encabezado se ignora, igual que en la biblioteca).
//   2. La hoja está firmada por el intermedio, y el intermedio es una autoridad (CA).
//   3. La hoja y el intermedio llevan las marcas propias de Apple (OID 1.2.840.113635.100.6.11.1 y 1.2.840.113635.100.6.2.1).
//   4. Los tres certificados están vigentes (con 60 s de tolerancia).
//   5. La firma ES256 del JWS es válida con la llave pública de la hoja.
//
// QUÉ NO COMPRUEBA: la revocación de los certificados (OCSP), porque la implementación de la biblioteca también depende del
// `X509Certificate` incompleto. El estado de la suscripción NO se toma del aviso: se vuelve a pedir a Apple con nuestra credencial.
import jsrsasign from "npm:jsrsasign@11.1.5";

// Import por defecto y no `{ X509 }`: así funciona igual en cualquier versión de Deno al cargar un módulo CommonJS.
const { X509, zulutodate } = jsrsasign;
type X509 = InstanceType<typeof jsrsasign.X509>;

const MAX_SKEW_MS = 60_000;
const LEAF_OID = "1.2.840.113635.100.6.11.1";
const INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1";

export type AppleJwsErrorKind =
  | "format" // no es un JWS legible
  | "chain_length" // x5c no trae 3 certificados
  | "untrusted" // la cadena no llega a una raíz de Apple fijada, o le faltan las marcas de Apple
  | "dates" // algún certificado fuera de vigencia
  | "signature"; // algoritmo distinto de ES256 o firma inválida

export class AppleJwsError extends Error {
  constructor(readonly kind: AppleJwsErrorKind) {
    super(`JWS de Apple no válido: ${kind}`);
    this.name = "AppleJwsError";
  }
}

function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Certificado en base64 (DER), como viene en `x5c`. */
export function loadCertificate(base64Der: string): X509 {
  const cert = new X509();
  cert.readCertHex(bytesToHex(base64ToBytes(base64Der)));
  return cert;
}

/** ¿Está `cert` firmado por `issuer`? (mismo emisor/sujeto y firma válida). Cualquier error de lectura cuenta como "no". */
export function isSignedBy(cert: X509, issuer: X509): boolean {
  try {
    return (
      cert.getIssuerHex() === issuer.getSubjectHex() &&
      cert.verifySignature(issuer.getPublicKey())
    );
  } catch {
    return false;
  }
}

/** ¿Está el certificado vigente en `now`, con la tolerancia de la biblioteca? */
export function isValidAt(cert: X509, now: Date): boolean {
  try {
    const from = zulutodate(cert.getNotBefore()).getTime();
    const to = zulutodate(cert.getNotAfter()).getTime();
    return (
      from <= now.getTime() + MAX_SKEW_MS && to >= now.getTime() - MAX_SKEW_MS
    );
  } catch {
    return false;
  }
}

function isCa(cert: X509): boolean {
  try {
    return cert.getExtBasicConstraints()?.cA === true;
  } catch {
    return false;
  }
}

function hasExtension(cert: X509, oid: string): boolean {
  try {
    return cert.getExtInfo(oid) !== undefined;
  } catch {
    return false;
  }
}

export interface VerifiedJws {
  header: Record<string, unknown>;
  payload: unknown;
}

/**
 * Verifica un JWS de Apple contra las raíces fijadas (`trustedRootsBase64`, DER en base64) y devuelve su contenido.
 * Lanza `AppleJwsError` con el motivo si algo no cuadra.
 */
export async function verifyAppleJws(
  jws: string,
  trustedRootsBase64: string[],
  now: Date = new Date(),
): Promise<VerifiedJws> {
  const parts = jws.split(".");
  if (parts.length !== 3) throw new AppleJwsError("format");

  const decoder = new TextDecoder();
  let header: Record<string, unknown>;
  let payload: unknown;
  try {
    header = JSON.parse(decoder.decode(base64UrlToBytes(parts[0])));
    payload = JSON.parse(decoder.decode(base64UrlToBytes(parts[1])));
  } catch {
    throw new AppleJwsError("format");
  }

  if (header.alg !== "ES256") throw new AppleJwsError("signature");

  const x5c = header.x5c;
  if (
    !Array.isArray(x5c) ||
    x5c.length !== 3 ||
    x5c.some((c) => typeof c !== "string")
  ) {
    throw new AppleJwsError("chain_length");
  }

  let leaf: X509;
  let intermediate: X509;
  let roots: X509[];
  try {
    leaf = loadCertificate(x5c[0]);
    intermediate = loadCertificate(x5c[1]);
    roots = trustedRootsBase64.map(loadCertificate);
  } catch {
    throw new AppleJwsError("untrusted");
  }

  const root = roots.find((r) => isSignedBy(intermediate, r));
  if (
    !root ||
    !isSignedBy(leaf, intermediate) ||
    !isCa(intermediate) ||
    !hasExtension(leaf, LEAF_OID) ||
    !hasExtension(intermediate, INTERMEDIATE_OID)
  ) {
    throw new AppleJwsError("untrusted");
  }
  if (![leaf, intermediate, root].every((c) => isValidAt(c, now))) {
    throw new AppleJwsError("dates");
  }

  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      hexToBytes(leaf.getPublicKeyHex()),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const signature = base64UrlToBytes(parts[2]);
    // ES256 en un JWS es r || s (64 bytes), el formato que WebCrypto espera.
    valid =
      signature.length === 64 &&
      (await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        signature,
        new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
      ));
  } catch {
    valid = false;
  }
  if (!valid) throw new AppleJwsError("signature");

  return { header, payload };
}
