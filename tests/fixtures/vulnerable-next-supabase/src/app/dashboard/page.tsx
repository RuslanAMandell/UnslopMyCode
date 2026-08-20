"use client";
import { useEffect, useState } from "react";
import { supabase } from "../../lib/supabase";

export default function Dashboard() {
  const [orders, setOrders] = useState<any[]>([]);

  async function load() {
    const { data } = await supabase.from("orders").select("*").order("created_at");
    const withUsers = [];
    for (const o of data ?? []) {
      const { data: u } = await supabase.from("profiles").select("*").eq("id", o.user_id);
      withUsers.push({ ...o, user: u?.[0] });
    }
    setOrders(withUsers);
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  }, []);

  return (
    <ul>
      {orders.map((o) => (
        <li key={o.id}>{o.user?.email} — {o.total_cents}</li>
      ))}
    </ul>
  );
}
