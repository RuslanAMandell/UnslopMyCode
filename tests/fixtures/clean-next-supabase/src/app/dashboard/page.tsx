"use client";
import { useEffect, useState } from "react";
import { supabase } from "../../lib/supabase";

const PAGE_SIZE = 25;

export default function Dashboard() {
  const [orders, setOrders] = useState<any[]>([]);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const { data, error } = await supabase
        .from("orders")
        .select("id, total_cents, created_at, profiles(email)")
        .order("created_at")
        .range(0, PAGE_SIZE - 1);

      if (cancelled) return;
      if (error) {
        setStatus("error");
        return;
      }
      setOrders(data ?? []);
      setStatus("ready");
    }

    load();
    const t = setInterval(load, 60000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  if (status === "loading") return <p>Loading orders…</p>;
  if (status === "error") return <p role="alert">Could not load orders.</p>;
  if (orders.length === 0) return <p>No orders yet.</p>;

  return (
    <ul>
      {orders.map((o) => (
        <li key={o.id}>{o.profiles?.email} — {o.total_cents}</li>
      ))}
    </ul>
  );
}
