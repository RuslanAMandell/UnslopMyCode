export function Checkout({ total }: { total: number }) {
  return <button disabled={total <= 0}>Pay {total}</button>;
}
