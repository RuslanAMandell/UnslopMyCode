import { z } from "zod";
import { logger } from "../../../lib/logger";
import { createServerClient } from "../../../lib/session";

const ALLOWED_REDIRECTS = new Set(["/orders", "/dashboard"]);

export async function GET(request: Request) {
  const { supabase, user } = await createServerClient();
  if (!user) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const url = new URL(request.url);
  const parsed = z.string().max(80).safeParse(url.searchParams.get("q") ?? "");
  if (!parsed.success) {
    return Response.json({ error: "invalid query" }, { status: 400 });
  }

  const { data, error } = await supabase
    .from("orders")
    .select("id, total_cents")
    .eq("user_id", user.id)
    .ilike("shipping_address", `%${parsed.data}%`)
    .limit(50);

  if (error) {
    logger.error("search failed", { requestId: crypto.randomUUID() });
    return Response.json({ error: "search unavailable" }, { status: 503 });
  }

  const next = url.searchParams.get("next");
  if (next && ALLOWED_REDIRECTS.has(next)) {
    return Response.redirect(new URL(next, url.origin));
  }

  return Response.json({ rows: data });
}
