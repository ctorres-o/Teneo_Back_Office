// Pruebas de la verificación de firmas de Apple. Se ejecutan con:  deno test supabase/functions/_shared/apple_jws_test.ts
// Usan una cadena de certificados de PRUEBA (apple_jws_fixtures.ts) y las raíces públicas reales de Apple (apple_roots.ts).
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  AppleJwsError,
  isSignedBy,
  isValidAt,
  loadCertificate,
  verifyAppleJws,
} from "./apple_jws.ts";
import { APPLE_ROOT_CAS_BASE64 } from "./apple_roots.ts";
import {
  TEST_INTERMEDIATE,
  TEST_LEAF,
  TEST_NOTIFICATION,
  TEST_NOTIFICATION_LEAF_WITHOUT_APPLE_MARK,
  TEST_ROOT,
  TEST_TRANSACTION,
} from "./apple_jws_fixtures.ts";

// Los certificados de prueba valen 100 años desde que se generaron (2026-10-15).
const NOW = new Date("2027-01-01T00:00:00Z");

function b64url(text: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(text)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromB64url(value: string): string {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

/** Cambia el encabezado de un JWS (la firma deja de valer, pero se rechaza por la regla que se está probando antes de llegar a ella). */
function withHeader(
  jws: string,
  change: (h: Record<string, unknown>) => void,
): string {
  const [h, p, s] = jws.split(".");
  const header = JSON.parse(fromB64url(h));
  change(header);
  return `${b64url(JSON.stringify(header))}.${p}.${s}`;
}

async function kindOf(
  jws: string,
  roots: string[],
  now = NOW,
): Promise<string> {
  const error = await assertRejects(
    () => verifyAppleJws(jws, roots, now),
    AppleJwsError,
  );
  return error.kind;
}

Deno.test(
  "un aviso firmado por la cadena de confianza se verifica y se devuelve su contenido",
  async () => {
    const { header, payload } = await verifyAppleJws(
      TEST_NOTIFICATION,
      [TEST_ROOT],
      NOW,
    );
    assertEquals(header.alg, "ES256");
    assertEquals(
      (payload as { notificationType: string }).notificationType,
      "TEST",
    );
    assertEquals(
      (payload as { data: { bundleId: string } }).data.bundleId,
      "com.netglobal.teneo",
    );
  },
);

Deno.test(
  "una transacción firmada por la cadena de confianza también se verifica",
  async () => {
    const { payload } = await verifyAppleJws(
      TEST_TRANSACTION,
      [TEST_ROOT],
      NOW,
    );
    assertEquals(
      (payload as { productId: string }).productId,
      "teneo.pro.monthly",
    );
  },
);

Deno.test(
  "si la raíz de la cadena no es una de las fijadas (por ejemplo, las reales de Apple), se rechaza",
  async () => {
    assertEquals(
      await kindOf(TEST_NOTIFICATION, APPLE_ROOT_CAS_BASE64),
      "untrusted",
    );
    assertEquals(await kindOf(TEST_NOTIFICATION, []), "untrusted");
  },
);

Deno.test(
  "una hoja sin la marca de Apple se rechaza aunque la cadena y la firma sean correctas",
  async () => {
    assertEquals(
      await kindOf(TEST_NOTIFICATION_LEAF_WITHOUT_APPLE_MARK, [TEST_ROOT]),
      "untrusted",
    );
  },
);

Deno.test(
  "si cambian el contenido del aviso, la firma deja de valer",
  async () => {
    const [h, p, s] = TEST_NOTIFICATION.split(".");
    const payload = JSON.parse(fromB64url(p));
    payload.notificationType = "REFUND";
    assertEquals(
      await kindOf(`${h}.${b64url(JSON.stringify(payload))}.${s}`, [TEST_ROOT]),
      "signature",
    );
  },
);

Deno.test("una firma de otro aviso, o dañada, se rechaza", async () => {
  const [h, p] = TEST_NOTIFICATION.split(".");
  const otherSignature =
    TEST_NOTIFICATION_LEAF_WITHOUT_APPLE_MARK.split(".")[2];
  assertEquals(
    await kindOf(`${h}.${p}.${otherSignature}`, [TEST_ROOT]),
    "signature",
  );
  assertEquals(await kindOf(`${h}.${p}.AAAA`, [TEST_ROOT]), "signature");
});

Deno.test(
  "un algoritmo distinto de ES256 se rechaza (nada de 'none' ni HS256)",
  async () => {
    assertEquals(
      await kindOf(
        withHeader(TEST_NOTIFICATION, (x) => (x.alg = "none")),
        [TEST_ROOT],
      ),
      "signature",
    );
    assertEquals(
      await kindOf(
        withHeader(TEST_NOTIFICATION, (x) => (x.alg = "HS256")),
        [TEST_ROOT],
      ),
      "signature",
    );
  },
);

Deno.test("la cadena debe traer exactamente 3 certificados", async () => {
  assertEquals(
    await kindOf(
      withHeader(
        TEST_NOTIFICATION,
        (x) => (x.x5c = [TEST_LEAF, TEST_INTERMEDIATE]),
      ),
      [TEST_ROOT],
    ),
    "chain_length",
  );
  assertEquals(
    await kindOf(
      withHeader(TEST_NOTIFICATION, (x) => delete x.x5c),
      [TEST_ROOT],
    ),
    "chain_length",
  );
});

Deno.test(
  "una cadena armada con el intermedio en lugar de la hoja, o con certificados dañados, se rechaza",
  async () => {
    assertEquals(
      await kindOf(
        withHeader(
          TEST_NOTIFICATION,
          (x) => (x.x5c = [TEST_INTERMEDIATE, TEST_INTERMEDIATE, TEST_ROOT]),
        ),
        [TEST_ROOT],
      ),
      "untrusted",
    );
    assertEquals(
      await kindOf(
        withHeader(
          TEST_NOTIFICATION,
          (x) => (x.x5c = ["AAAA", "BBBB", "CCCC"]),
        ),
        [TEST_ROOT],
      ),
      "untrusted",
    );
  },
);

Deno.test(
  "con los certificados vencidos (o todavía no vigentes) se rechaza",
  async () => {
    assertEquals(
      await kindOf(
        TEST_NOTIFICATION,
        [TEST_ROOT],
        new Date("2300-01-01T00:00:00Z"),
      ),
      "dates",
    );
    assertEquals(
      await kindOf(
        TEST_NOTIFICATION,
        [TEST_ROOT],
        new Date("2000-01-01T00:00:00Z"),
      ),
      "dates",
    );
  },
);

Deno.test("lo que no es un JWS se rechaza como formato", async () => {
  for (const text of ["", "abc", "a.b", "a.b.c.d", "....", "e30.e30.e30"]) {
    const kind = await kindOf(text, [TEST_ROOT]);
    assert(
      kind === "format" || kind === "signature" || kind === "chain_length",
      `inesperado para "${text}": ${kind}`,
    );
  }
  assertEquals(await kindOf("!!!.!!!.!!!", [TEST_ROOT]), "format");
});

Deno.test(
  "las raíces reales de Apple que fijamos se leen, están firmadas por sí mismas y vigentes",
  () => {
    assert(APPLE_ROOT_CAS_BASE64.length >= 1);
    for (const b64 of APPLE_ROOT_CAS_BASE64) {
      const root = loadCertificate(b64);
      assert(
        isSignedBy(root, root),
        "una raíz debe estar firmada por sí misma",
      );
      assert(
        isValidAt(root, new Date()),
        "una raíz de Apple fijada debe estar vigente",
      );
    }
  },
);
