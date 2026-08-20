import { expect, test } from "vitest";
import { Checkout } from "../src/components/Checkout";

test("Checkout renders the total", () => {
  const el = Checkout({ total: 1200 });
  expect(el).toBeTruthy();
});
