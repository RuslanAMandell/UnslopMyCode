const hits = new Map<string, { count: number; resetAt: number }>();

export async function rateLimit(
  request: Request,
  opts: { key: string; max: number; windowMs: number }
): Promise<boolean> {
  const ip = request.headers.get("x-forwarded-for") ?? "unknown";
  const bucket = `${opts.key}:${ip}`;
  const now = Date.now();
  const entry = hits.get(bucket);

  if (!entry || entry.resetAt < now) {
    hits.set(bucket, { count: 1, resetAt: now + opts.windowMs });
    return true;
  }
  entry.count += 1;
  return entry.count <= opts.max;
}
