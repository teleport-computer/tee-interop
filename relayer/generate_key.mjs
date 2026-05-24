#!/usr/bin/env node
// Generate a fresh relayer wallet. Prints the address to stdout, the private
// key to stderr (so you can `node generate_key.mjs 2> .relayer.key`).
//
// Do not commit the resulting key. Add to wrangler:
//   wrangler secret put RELAYER_KEY < .relayer.key
import { Wallet } from "ethers";

const w = Wallet.createRandom();
console.log(w.address);
console.error(w.privateKey);
