// Guarding a withdrawal with 2F.
//   TWOF_URL=http://localhost:8722 TWOF_API_KEY=2f_... TWOF_KID=... TWOF_PUBLIC_KEY=... node examples/withdraw.mjs

import { TwoF } from "../sdk/ts/index.js";

const twof = new TwoF({
  url: process.env.TWOF_URL,
  apiKey: process.env.TWOF_API_KEY,
  // From `twof pubkey`. Pinned here, never fetched from the server.
  publicKeys: { [process.env.TWOF_KID]: process.env.TWOF_PUBLIC_KEY },
});

const action = { type: "withdraw", amount: "2500.00", asset: "USDT", destination: "0xabc...", meta: { order: "A-1042" } };

const result = await twof.authorize(action, {
  // One key per business operation: retrying is safe, and a second
  // different action under the same key is refused.
  idempotencyKey: "withdraw-A-1042",
  onPending: (challenge) => console.log("waiting for approval:", challenge.approve_url),
});

if (!result.authorized) {
  console.log("not authorized:", result.state);
  process.exit(1);
}

// The receipt was verified for exactly `action`. Mark it used, then execute.
await twof.consume(result.receipt);
console.log("authorized by rule:", result.payload.rule);
// sendWithdrawal(action) goes here, using the same `action` object.
