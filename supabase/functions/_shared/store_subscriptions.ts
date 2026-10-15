// Lado base de datos de las suscripciones de tienda. Escribe con la llave de servicio: la app nunca escribe `subscriptions`.
//
// Reglas (MATRIZ_DE_PLANES.md, principios de diseño):
//  1. Propiedad: una misma compra (original_transaction_id) solo puede estar ligada a UNA cuenta. Si ya es de otra cuenta, se rechaza;
//     si es de la misma cuenta, se actualiza (por ejemplo al restaurar compras).
//  2. Vigencia: la fecha de término es obligatoria en una compra de tienda y viene de Apple.
//  3. Conservación: aquí nunca se borra nada; un vencimiento solo cambia el estado de la fila.
import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2";
import type { AppleSubscriptionState } from "./apple.ts";

/** El producto de Apple no está en `subscription_products` (o está desactivado). */
export class UnknownProductError extends Error {}
/** La compra ya está ligada a otra cuenta de Teneo. */
export class OwnedByAnotherAccountError extends Error {}
/** Apple no entregó una fecha de término para una compra de tienda. */
export class MissingEndDateError extends Error {}

export function adminClient(): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key)
    throw new Error(
      "Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en la función.",
    );
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

interface Product {
  plan: "pro" | "premium";
  billing_cycle: "monthly" | "annual";
}

async function productFor(
  admin: SupabaseClient,
  productId: string,
): Promise<Product> {
  const { data, error } = await admin
    .from("subscription_products")
    .select("plan, billing_cycle, active")
    .eq("store", "apple")
    .eq("product_id", productId)
    .eq("base_plan_id", "")
    .maybeSingle();
  if (error) throw error;
  if (!data || !data.active)
    throw new UnknownProductError(
      `Producto de Apple desconocido: ${productId}`,
    );
  return data as Product;
}

function rowFrom(state: AppleSubscriptionState, product: Product) {
  if (!state.expiresDate)
    throw new MissingEndDateError(
      "Apple no entregó la fecha de término de la suscripción.",
    );
  return {
    plan: product.plan,
    plan_name: product.plan === "premium" ? "Premium" : "Pro",
    status: state.status,
    payment_method: "apple",
    billing_cycle: product.billing_cycle,
    product_id: state.productId,
    transaction_id: state.transactionId,
    original_transaction_id: state.originalTransactionId,
    start_date: state.purchaseDate ? state.purchaseDate.toISOString() : null,
    end_date: state.expiresDate.toISOString(),
    auto_renew: state.autoRenew,
    environment: state.environment,
    price: state.price,
  };
}

type SubscriptionRow = Record<string, unknown>;

/** Compra o restauración hecha por una persona identificada: crea o actualiza SU suscripción. */
export async function applyForOwner(
  admin: SupabaseClient,
  ownerId: string,
  state: AppleSubscriptionState,
): Promise<SubscriptionRow> {
  const product = await productFor(admin, state.productId);
  const row = rowFrom(state, product);

  const { data: byTx, error: byTxError } = await admin
    .from("subscriptions")
    .select("id, owner_id")
    .eq("original_transaction_id", state.originalTransactionId)
    .maybeSingle();
  if (byTxError) throw byTxError;
  if (byTx && byTx.owner_id !== ownerId) {
    throw new OwnedByAnotherAccountError(
      "Esta compra ya está asociada a otra cuenta de Teneo.",
    );
  }

  const { data: mine, error: mineError } = await admin
    .from("subscriptions")
    .select("*")
    .eq("owner_id", ownerId)
    .maybeSingle();
  if (mineError) throw mineError;

  // Una compra vencida o sin cobrar no pisa una suscripción distinta que la persona ya tiene.
  if (
    mine &&
    mine.original_transaction_id !== state.originalTransactionId &&
    state.status !== "active"
  ) {
    return mine;
  }

  const query = mine
    ? admin.from("subscriptions").update(row).eq("id", mine.id)
    : admin.from("subscriptions").insert({ ...row, owner_id: ownerId });
  const { data, error } = await query.select().single();
  if (error) {
    // 23505 = violación de unicidad: otra cuenta ligó esta compra justo ahora.
    if (error.code === "23505") {
      throw new OwnedByAnotherAccountError(
        "Esta compra ya está asociada a otra cuenta de Teneo.",
      );
    }
    throw error;
  }
  return data;
}

/** Aviso de Apple: actualiza la fila que ya tiene esa compra. Si todavía no existe, no hace nada (la crea verify-purchase). */
export async function applyFromNotification(
  admin: SupabaseClient,
  state: AppleSubscriptionState,
): Promise<{ applied: boolean; ownerId: string | null }> {
  const { data: existing, error: findError } = await admin
    .from("subscriptions")
    .select("id, owner_id")
    .eq("original_transaction_id", state.originalTransactionId)
    .maybeSingle();
  if (findError) throw findError;
  if (!existing) return { applied: false, ownerId: null };

  const product = await productFor(admin, state.productId);
  const { error } = await admin
    .from("subscriptions")
    .update(rowFrom(state, product))
    .eq("id", existing.id);
  if (error) throw error;
  return { applied: true, ownerId: existing.owner_id };
}

/** Registra un aviso de la tienda. Si ya se procesó antes, `alreadyProcessed` es true y no hay que repetirlo. */
export async function beginEvent(
  admin: SupabaseClient,
  store: "apple" | "google",
  eventId: string,
  eventType: string,
  payload: Record<string, unknown>,
): Promise<{ id: string; alreadyProcessed: boolean }> {
  const find = () =>
    admin
      .from("subscription_events")
      .select("id, processed_at")
      .eq("store", store)
      .eq("event_id", eventId)
      .maybeSingle();

  const { data: existing, error: findError } = await find();
  if (findError) throw findError;
  if (existing)
    return { id: existing.id, alreadyProcessed: existing.processed_at != null };

  const { data, error } = await admin
    .from("subscription_events")
    .insert({ store, event_id: eventId, event_type: eventType, payload })
    .select("id")
    .single();
  if (error) {
    if (error.code === "23505") {
      const { data: again } = await find();
      if (again)
        return { id: again.id, alreadyProcessed: again.processed_at != null };
    }
    throw error;
  }
  return { id: data.id, alreadyProcessed: false };
}

/** Deja constancia de cómo terminó el aviso. */
export async function finishEvent(
  admin: SupabaseClient,
  id: string,
  ownerId: string | null,
  result: string,
  processed: boolean,
): Promise<void> {
  await admin
    .from("subscription_events")
    .update({
      owner_id: ownerId,
      result,
      processed_at: processed ? new Date().toISOString() : null,
    })
    .eq("id", id);
}
