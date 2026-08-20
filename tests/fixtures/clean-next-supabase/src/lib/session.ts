import "server-only";
import { cookies } from "next/headers";
import { supabaseAdmin } from "./supabase-admin";

export async function createServerClient() {
  const token = cookies().get("session")?.value;
  if (!token) {
    return { supabase: supabaseAdmin, user: null };
  }
  const { data } = await supabaseAdmin.auth.getUser(token);
  return { supabase: supabaseAdmin, user: data?.user ?? null };
}
