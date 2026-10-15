// "Invitar co-tutor" — la app llama a esta función con la sesión del administrador. Ella crea la invitación llamando a la función
// de base de datos `invite_caregiver` (que revisa el plan, el tope, el correo y los duplicados) y, si salió bien, envía el correo de
// invitación con Resend (el mismo servicio y remitente que `share-pet`).
//
// Se corre con el JWT del administrador (no con la llave de servicio): toda la autorización real la resuelve la base de datos,
// igual que en `share-pet`.
//
// Entrada:  { email: string, replaces_id?: string }
// Salida:   { invitation: {...fila de pet_caregivers...}, email_sent: boolean }  o  { error: "codigo_corto" }
//   El código es el texto corto que lanza la base (por ejemplo "caregiver_limit_reached"); la app lo traduce a español.
//   Si la invitación se creó pero el correo falló, responde 200 con email_sent = false: la invitación igual existe y la
//   persona la verá al entrar a la app con ese correo.
import { createClient } from "npm:@supabase/supabase-js@2";

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

// Los nombres vienen de personas: se escapan antes de ir dentro del HTML del correo.
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const APP_STORE_URL = "https://apps.apple.com/app/id6808037892";
const GOOGLE_PLAY_URL =
  "https://play.google.com/store/apps/details?id=com.netglobal.teneo";

function buildEmail(adminName: string): { subject: string; html: string } {
  const name = escapeHtml(adminName);
  const subject = `${adminName} te invitó a cuidar a sus mascotas en Teneo`;
  const html = `
      <div style="font-family: Helvetica, Arial, sans-serif; color: #131214; max-width: 480px; margin: 0 auto;">
        <p style="font-size: 18px; font-weight: bold; color: #4160e9; margin-bottom: 24px;">Teneo Pet</p>
        <p><strong>${name}</strong> te invitó a ser co-tutor de sus mascotas en Teneo. Podrás ver y editar su historial.</p>
        <ol style="padding-left: 20px; line-height: 1.6;">
          <li>Descarga la app Teneo: <a href="${APP_STORE_URL}">App Store</a> · <a href="${GOOGLE_PLAY_URL}">Google Play</a>.</li>
          <li>Regístrate o inicia sesión con <strong>este correo</strong> (el mismo al que llegó este mensaje).</li>
          <li>Acepta la invitación que verás al entrar.</li>
        </ol>
        <p style="color: #6e7375; font-size: 12px; margin-top: 32px;">Si no conoces a ${name}, puedes ignorar este mensaje.</p>
      </div>
    `;
  return { subject, html };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS")
    return new Response(null, { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) return json({ error: "not_authenticated" }, 401);

    let body: { email?: unknown; replaces_id?: unknown };
    try {
      body = await req.json();
    } catch {
      return json({ error: "invalid_email" }, 400);
    }
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const replacesId =
      typeof body.replaces_id === "string" ? body.replaces_id : null;

    // Cliente con el JWT del administrador: todo lo que sigue corre con SU sesión.
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: authHeader } } },
    );
    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser();
    if (userError || !user) return json({ error: "not_authenticated" }, 401);

    const { data: invitation, error: inviteError } = await supabase.rpc(
      "invite_caregiver",
      { p_email: email, p_replaces: replacesId },
    );
    if (inviteError) {
      // P0001 = error de negocio lanzado por la base con RAISE EXCEPTION: el mensaje es el código corto.
      if (inviteError.code === "P0001") {
        return json({ error: inviteError.message }, 400);
      }
      console.error("invite-caregiver: la base falló:", inviteError.message);
      return json({ error: "unexpected" }, 500);
    }

    // La invitación ya existe. Desde aquí, un fallo del correo no la deshace.
    let emailSent = false;
    const resendApiKey = Deno.env.get("RESEND_API_KEY");
    const fromAddress = Deno.env.get("SHARE_EMAIL_FROM");
    if (!resendApiKey || !fromAddress) {
      console.error(
        "invite-caregiver: faltan RESEND_API_KEY o SHARE_EMAIL_FROM; no se envió el correo.",
      );
    } else {
      try {
        const { data: owner } = await supabase
          .from("owners")
          .select("first_name, last_name")
          .eq("user_id", user.id)
          .maybeSingle();
        const adminName =
          [owner?.first_name, owner?.last_name]
            .filter((part): part is string => !!part && part.trim() !== "")
            .join(" ") || "Un tutor de Teneo";
        const { subject, html } = buildEmail(adminName);
        const res = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${resendApiKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            from: fromAddress,
            to: email.toLowerCase(),
            subject,
            html,
          }),
        });
        emailSent = res.ok;
        if (!res.ok) {
          console.error(
            "invite-caregiver: Resend rechazó el envío:",
            await res.text(),
          );
        }
      } catch (err) {
        console.error("invite-caregiver: el envío del correo falló:", err);
      }
    }

    return json({ invitation, email_sent: emailSent });
  } catch (err) {
    console.error("invite-caregiver crashed:", err);
    return json({ error: "unexpected" }, 500);
  }
});
