import { cookies } from "next/headers";
import { z } from "zod";
import { rateLimit } from "../../../lib/rate-limit";
import { supabase } from "../../../lib/supabase";

const Body = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(200),
});

export async function POST(request: Request) {
  const allowed = await rateLimit(request, { key: "login", max: 5, windowMs: 60_000 });
  if (!allowed) {
    return Response.json({ error: "too many attempts" }, { status: 429 });
  }

  const parsed = Body.safeParse(await request.json());
  if (!parsed.success) {
    return Response.json({ error: "invalid request" }, { status: 400 });
  }

  const { data, error } = await supabase.auth.signInWithPassword(parsed.data);
  if (error || !data.session) {
    return Response.json({ error: "invalid credentials" }, { status: 401 });
  }

  cookies().set("session", data.session.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
  });

  return Response.json({ ok: true });
}
