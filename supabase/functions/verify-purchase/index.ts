// "Validar compra" — la app la llama justo después de comprar o restaurar una suscripción (ver
// `SubscriptionService.verifyPurchase` en Teneo-App). Esta función NO se fía de lo que diga la app: identifica a la persona por su
// sesión, le pregunta a Apple el estado real de la compra y guarda la suscripción con la llave de servicio.
//
// Entrada:  { platform: "apple" | "google", product_id, transaction_id (iOS) | purchase_token (Android) }
// Salida:   { subscription: {...fila de subscriptions...} }  o  { error: "texto para mostrar" }
//
// Despliegue: con verificación de JWT activada (valor por defecto): solo entra gente con sesión de Teneo.
import {
  AppleConfigError,
  AppleNotFoundError,
  describeAppleError,
  fetchSubscriptionState,
} from "../_shared/apple.ts";
import {
  adminClient,
  applyForOwner,
  MissingEndDateError,
  OwnedByAnotherAccountError,
  UnknownProductError,
} from "../_shared/store_subscriptions.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS")
    return new Response(null, { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const token = req.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
    if (!token)
      return json({ error: "Falta la sesión (header Authorization)." }, 401);

    const admin = adminClient();
    const { data: userData, error: userError } =
      await admin.auth.getUser(token);
    if (userError || !userData.user)
      return json(
        { error: "La sesión no es válida. Vuelve a iniciar sesión." },
        401,
      );
    const ownerId = userData.user.id;

    let body: {
      platform?: string;
      product_id?: string;
      transaction_id?: string;
    };
    try {
      body = await req.json();
    } catch {
      return json({ error: "El cuerpo de la solicitud no es JSON." }, 400);
    }

    if (body.platform === "google") {
      return json(
        { error: "Las compras de Google Play todavía no están habilitadas." },
        501,
      );
    }
    if (body.platform !== "apple")
      return json({ error: "Plataforma no reconocida." }, 400);
    const transactionId = body.transaction_id?.trim();
    if (!transactionId)
      return json({ error: "Falta el identificador de la transacción." }, 400);

    const state = await fetchSubscriptionState(transactionId);
    const subscription = await applyForOwner(admin, ownerId, state);
    return json({ subscription });
  } catch (e) {
    if (e instanceof OwnedByAnotherAccountError)
      return json({ error: e.message }, 409);
    if (e instanceof AppleNotFoundError) {
      return json(
        {
          error:
            "Apple no reconoce esta compra. Si acabas de pagar, espera un momento y vuelve a intentarlo.",
        },
        404,
      );
    }
    if (e instanceof UnknownProductError || e instanceof MissingEndDateError) {
      console.error("verify-purchase:", e.message);
      return json(
        {
          error:
            "No se pudo identificar el plan de esta compra. Contáctanos y la revisamos.",
        },
        422,
      );
    }
    if (e instanceof AppleConfigError) {
      // El detalle (qué secretos faltan) queda en los registros de la función, no se muestra a la persona.
      console.error("verify-purchase:", e.message);
      return json(
        { error: "El servicio de compras no está configurado todavía." },
        500,
      );
    }
    console.error("verify-purchase:", describeAppleError(e));
    return json(
      {
        error: "No se pudo validar la compra. Se reintentará automáticamente.",
      },
      502,
    );
  }
});
