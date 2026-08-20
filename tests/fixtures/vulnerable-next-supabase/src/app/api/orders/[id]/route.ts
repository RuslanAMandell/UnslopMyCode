import { supabase } from "../../../../lib/supabase";

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const { data } = await supabase
      .from("orders")
      .select("*")
      .eq("user_id", params.id);

    const enrich = await fetch(`https://ship.example.com/track/${params.id}`);
    const tracking = await enrich.json();

    return Response.json({ order: data, tracking });
  } catch (err) {
    return new Response(JSON.stringify({ error: (err as Error).stack }), { status: 500 });
  }
}
