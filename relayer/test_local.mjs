#!/usr/bin/env node
// Local dry-run for the Worker. Imports the fetch handler directly and calls
// it like Cloudflare would.
//
// Prereq: anvil at $RPC with MockVerifier @ $VERIFIER and PixelFaucet @ $FAUCET.
// All addresses + the relayer key come from env vars (sourced from /tmp/faucet-test/env).
//
// Posts the AGREE_KEY fixture PEM at test/fixtures/pixel6_strongbox.pem with a
// fixed target address and a "hello" message. Expects the Worker handler to:
//   - recompute the binding hash
//   - ABI-encode + view-call MockVerifier.verify()
//   - sign a permit
//   - call PixelFaucet.claim()
// We then read back the Tagged event to confirm the chain ran clean.
import { readFileSync } from "node:fs";
import { JsonRpcProvider, Contract } from "ethers";
import worker from "./index.js";

const RPC = process.env.RPC;
const FAUCET = process.env.FAUCET;
const VERIFIER = process.env.MOCK;
const RELAYER_KEY = process.env.RELAYER_PRIVKEY;
const TO = "0x0000000000000000000000000000000000001234";
const MESSAGE = "hello from anvil dry-run";

const pem = readFileSync("../test/fixtures/pixel6_strongbox.pem", "utf8");

const env = {
    RPC_URL: RPC,
    VERIFIER_ADDRESS: VERIFIER,
    FAUCET_ADDRESS: FAUCET,
    RELAYER_KEY,
};

const makeReq = () => new Request("http://local/", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ pem, to: TO, message: MESSAGE }),
});

const resp = await worker.fetch(makeReq(), env);
const body = await resp.json();
console.log("status:", resp.status);
console.log("body:", JSON.stringify(body, null, 2));

if (!resp.ok) {
    process.exit(1);
}

// Wait for the tx, read back the Tagged event.
const provider = new JsonRpcProvider(RPC);
const ABI = [
    "event Tagged(bytes32 indexed deviceFingerprint, address indexed to, string message, bytes32 pemHash, bytes32 codeId, uint256 timestamp)",
    "function taggedCount() view returns (uint256)",
    "function claimed(bytes32) view returns (bool)",
];
const faucet = new Contract(FAUCET, ABI, provider);

const receipt = await provider.waitForTransaction(body.txHash);
console.log("---");
console.log("tx mined block:", receipt.blockNumber, "gas:", receipt.gasUsed.toString());

const events = await faucet.queryFilter(faucet.filters.Tagged(), receipt.blockNumber, receipt.blockNumber);
if (events.length === 0) {
    console.error("FAIL: no Tagged event");
    process.exit(1);
}
const ev = events[0];
console.log("Tagged event:");
console.log("  deviceFingerprint:", ev.args.deviceFingerprint);
console.log("  to:", ev.args.to);
console.log("  message:", JSON.stringify(ev.args.message));
console.log("  pemHash:", ev.args.pemHash);
console.log("  codeId:", ev.args.codeId);
console.log("  timestamp:", ev.args.timestamp.toString());

const count = await faucet.taggedCount();
const isClaimed = await faucet.claimed(ev.args.deviceFingerprint);
console.log("taggedCount:", count.toString());
console.log("claimed[fingerprint]:", isClaimed);

// Pre-check: second call should short-circuit on faucet.claimed(fp) check
// and return 200 with alreadyClaimed=true, WITHOUT submitting a doomed tx.
console.log("---");
console.log("re-submitting same chain, expecting alreadyClaimed short-circuit (no gas spent)...");
const blockBefore = await provider.getBlockNumber();
const resp2 = await worker.fetch(makeReq(), env);
const body2 = await resp2.json();
const blockAfter = await provider.getBlockNumber();
console.log("status:", resp2.status);
console.log("body:", JSON.stringify(body2, null, 2));
console.log("blocks advanced:", blockAfter - blockBefore);

if (!resp2.ok) {
    console.error("FAIL: expected 200 with alreadyClaimed, got error:", body2.error);
    process.exit(1);
}
if (!body2.alreadyClaimed) {
    console.error("FAIL: alreadyClaimed flag missing");
    process.exit(1);
}
if (blockAfter !== blockBefore) {
    console.error("FAIL: relayer submitted a tx anyway (waste of gas)");
    process.exit(1);
}
if (!body2.original || body2.original.txHash !== body.txHash) {
    console.error("FAIL: original Tagged event not surfaced", body2.original);
    process.exit(1);
}
console.log("✓ short-circuited with original tx hash, zero gas spent on repeat");

console.log("---\nOK");
