import { createServerClient } from "../../../../lib/session";

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const { supabase, user } = await createServerClient();
  if (!user) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const { data, error } = await supabase
    .from("orders")
    .select("id, total_cents, created_at")
    .eq("id", params.id)
    .eq("user_id", user.id)
    .limit(1);

  if (error || !data || data.length === 0) {
    return Response.json({ error: "not found" }, { status: 404 });
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const enrich = await fetch(`https://ship.example.com/track/${params.id}`, {
      signal: controller.signal,
    });
    if (!enrich.ok) {
      return Response.json({ order: data[0], tracking: null });
    }
    const tracking = await enrich.json();
    return Response.json({ order: data[0], tracking });
  } finally {
    clearTimeout(timer);
  }
}
