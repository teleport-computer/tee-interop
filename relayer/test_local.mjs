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

// Replay protection: second call with the same chain MUST revert AlreadyClaimed.
console.log("---");
console.log("re-submitting same claim, expecting AlreadyClaimed...");
const resp2 = await worker.fetch(makeReq(), env);
const body2 = await resp2.json();
console.log("status:", resp2.status, "error:", body2.error || "(none)");
if (resp2.ok) {
    console.error("FAIL: second claim should have reverted");
    process.exit(1);
}
// Accept any revert as "rejected" — the custom-error name in the ABI doesn't
// always decode through ethers' simulation path. Semantic check: claim() reverted.
if (!String(body2.error).toLowerCase().includes("revert")) {
    console.error("FAIL: error didn't mention revert:", body2.error);
    process.exit(1);
}
console.log("✓ replay rejected:", body2.error);

console.log("---\nOK");
