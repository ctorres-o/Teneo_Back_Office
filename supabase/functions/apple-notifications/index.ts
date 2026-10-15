// Avisos del servidor de la App Store (App Store Server Notifications V2). Apple llama a esta función sola cuando una suscripción
// se renueva, se cancela, vence, falla un cobro o se reembolsa. Sin ella, un plan cancelado seguiría activo hasta la fecha de término.
//
// Seguridad: Apple NO manda una sesión de Supabase, así que esta función se despliega SIN verificación de JWT
// (`supabase functions deploy apple-notifications --no-verify-jwt`). La protección es la firma de Apple: cada aviso se verifica
// contra la cadena de certificados de Apple y contra nuestro bundle ID; cualquier otra cosa recibe 400.
//
// Criterio: el aviso solo sirve de "despertador". El estado se vuelve a pedir a Apple (fuente de la verdad), así que el orden en que
// lleguen los avisos o que lleguen repetidos no importa.
//
// URL para App Store Connect (Información de la app > Notificaciones del servidor, producción y sandbox):
//   https://<proyecto>.supabase.co/functions/v1/apple-notifications
import {
  AppleConfigError,
  decodeNotification,
  describeAppleError,
  fetchSubscriptionState,
} from "../_shared/apple.ts";
import {
  adminClient,
  applyFromNotification,
  beginEvent,
  finishEvent,
} from "../_shared/store_subscriptions.ts";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  let signedPayload: string | undefined;
  try {
    signedPayload = (await req.json())?.signedPayload;
  } catch {
    return json({ error: "Cuerpo no válido." }, 400);
  }
  if (!signedPayload || typeof signedPayload !== "string")
    return json({ error: "Falta signedPayload." }, 400);

  let notification;
  try {
    notification = await decodeNotification(signedPayload);
  } catch (e) {
    if (e instanceof AppleConfigError) {
      console.error("apple-notifications:", e.message);
      return json({ error: "Servicio no configurado." }, 500);
    }
    // Firma, bundle o entorno que no cuadran: no viene de Apple.
    console.error(
      "apple-notifications: aviso rechazado:",
      describeAppleError(e),
    );
    return json({ error: "Aviso no válido." }, 400);
  }
  if (!notification.notificationUUID)
    return json({ error: "El aviso no trae identificador." }, 400);

  const admin = adminClient();
  const type = notification.subtype
    ? `${notification.notificationType}:${notification.subtype}`
    : notification.notificationType;

  let eventId: string;
  try {
    const event = await beginEvent(
      admin,
      "apple",
      notification.notificationUUID,
      type,
      {
        environment: notification.environment,
        notificationType: notification.notificationType,
        subtype: notification.subtype,
      },
    );
    if (event.alreadyProcessed) return json({ ok: true, duplicate: true });
    eventId = event.id;
  } catch (e) {
    console.error(
      "apple-notifications: no se pudo registrar el aviso:",
      describeAppleError(e),
    );
    return json({ error: "No se pudo registrar el aviso." }, 500);
  }

  // Avisos sin transacción (por ejemplo el de prueba de App Store Connect): se registran y listo.
  if (!notification.transactionId) {
    await finishEvent(
      admin,
      eventId,
      null,
      "sin transacción: no requiere cambios",
      true,
    );
    return json({ ok: true });
  }

  try {
    const state = await fetchSubscriptionState(notification.transactionId);
    const result = await applyFromNotification(admin, state);
    await finishEvent(
      admin,
      eventId,
      result.ownerId,
      result.applied
        ? `aplicado: estado ${state.status}`
        : "sin fila todavía: la crea verify-purchase",
      true,
    );
    return json({ ok: true });
  } catch (e) {
    // Se deja sin marcar como procesado y se responde 500: Apple reintenta.
    const message = describeAppleError(e);
    console.error("apple-notifications: error al procesar:", message);
    await finishEvent(admin, eventId, null, `error: ${message}`, false);
    return json({ error: "No se pudo procesar el aviso." }, 500);
  }
});
