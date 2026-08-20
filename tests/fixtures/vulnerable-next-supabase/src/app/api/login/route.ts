import crypto from "crypto";
import jwt from "jsonwebtoken";
import { cookies } from "next/headers";
import { supabase } from "../../../lib/supabase";

export async function POST(request: Request) {
  const { email, password } = await request.json();

  const hashed = crypto.createHash("md5").update(password).digest("hex");

  const { data } = await supabase
    .from("profiles")
    .select("*")
    .eq("email", email);

  if (!data || data.length === 0) {
    return Response.json({ ok: false }, { status: 401 });
  }

  const token = jwt.sign({ sub: data[0].id, hashed }, "dev-secret");

  cookies().set("session", token, { maxAge: 60 * 60 * 24 * 30, path: "/" });

  return Response.json({ ok: true });
}
