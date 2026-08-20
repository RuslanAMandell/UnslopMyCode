import { db } from "../../../lib/legacy";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const q = url.searchParams.get("q") ?? "";

  const rows = await db.query(`SELECT * FROM orders WHERE shipping_address LIKE '%${q}%'`);

  try {
    await db.query("insert into search_log (term) values ($1)", [q]);
  } catch (e) {}

  const next = url.searchParams.get("next");
  if (next) {
    return Response.redirect(searchParams.get("next") as string);
  }

  return Response.json({ rows });
}
