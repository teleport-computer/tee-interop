// Cloudflare Worker relayer for the Pixel faucet demo.
//
// Flow:
//   1. APK POSTs { pem, to, message } here.
//   2. We compute the expected attestation challenge:
//        SHA256( "pixel-faucet/v1" || chainId_be8 || faucet || to || sha256(message) )
//   3. ABI-encode the proof and view-call AndroidKeyAttestationVerifier.verify().
//      That returns (codeId, pubkey, userData) iff the chain signatures + root pin
//      + on-chain extension policy all pass. We confirm userData equals our
//      recomputed challenge so the device proved it bound exactly these params.
//   4. Sign a claim permit with the relayer key and submit faucet.claim(...).
//
// Env vars (set via `wrangler secret put`):
//   RELAYER_KEY        - 0x-prefixed private key for the relayer wallet
// Vars (set in wrangler.toml):
//   RPC_URL            - Base Sepolia RPC
//   VERIFIER_ADDRESS   - AndroidKeyAttestationVerifier
//   FAUCET_ADDRESS     - PixelFaucet
import {
    AbiCoder, Contract, JsonRpcProvider, Wallet,
    getAddress, getBytes, hexlify, keccak256, toUtf8Bytes,
} from "ethers";

const VERIFIER_ABI = [
    "function verify(bytes proof) view returns (bytes32 codeId, bytes pubkey, bytes userData)",
];
const FAUCET_ABI = [
    "function claim(bytes32 deviceFingerprint, address to, string message, bytes32 pemHash, bytes32 codeId, uint256 deadline, bytes relayerSig)",
    "function claimed(bytes32) view returns (bool)",
    "event Tagged(bytes32 indexed deviceFingerprint, address indexed to, string message, bytes32 pemHash, bytes32 codeId, uint256 timestamp)",
    "error AlreadyClaimed()",
    "error Expired()",
    "error BadRelayerSig()",
    "error MessageTooLong()",
    "error ZeroFingerprint()",
    "error NotOwner()",
];
const DOMAIN = "pixel-faucet/v1";
const PERMIT_TTL_SECONDS = 600;

function parsePem(text) {
    const out = [];
    const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
    let m;
    while ((m = re.exec(text)) !== null) {
        const b64 = m[1].replace(/\s+/g, "");
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        out.push(hexlify(bytes));
    }
    return out;
}

async function sha256(bytes) {
    const buf = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(buf);
}

async function computeBinding(chainId, faucetAddr, toAddr, message) {
    const domain = toUtf8Bytes(DOMAIN);
    const chainIdBytes = new Uint8Array(8);
    new DataView(chainIdBytes.buffer).setBigUint64(0, BigInt(chainId), false);
    const faucet = getBytes(getAddress(faucetAddr));
    const to = getBytes(getAddress(toAddr));
    const msgHash = await sha256(toUtf8Bytes(message));

    const combined = new Uint8Array(domain.length + 8 + 20 + 20 + 32);
    let o = 0;
    combined.set(domain, o); o += domain.length;
    combined.set(chainIdBytes, o); o += 8;
    combined.set(faucet, o); o += 20;
    combined.set(to, o); o += 20;
    combined.set(msgHash, o);
    return hexlify(await sha256(combined));
}

const cors = (resp) => {
    resp.headers.set("access-control-allow-origin", "*");
    resp.headers.set("access-control-allow-headers", "content-type");
    resp.headers.set("access-control-allow-methods", "POST, OPTIONS");
    return resp;
};
const json = (body, status = 200) =>
    cors(new Response(JSON.stringify(body), {
        status, headers: { "content-type": "application/json" },
    }));

export default {
    async fetch(req, env) {
        if (req.method === "OPTIONS") return cors(new Response(null, { status: 204 }));
        if (req.method === "GET") {
            return json({
                ok: true,
                domain: DOMAIN,
                verifier: env.VERIFIER_ADDRESS,
                faucet: env.FAUCET_ADDRESS,
            });
        }
        if (req.method !== "POST") return json({ error: "POST only" }, 405);

        let body;
        try { body = await req.json(); }
        catch { return json({ error: "invalid JSON" }, 400); }

        const { pem, to, message } = body ?? {};
        if (!pem || !to || typeof message !== "string") {
            return json({ error: "missing pem|to|message" }, 400);
        }
        if (!/^0x[0-9a-fA-F]{40}$/.test(to)) {
            return json({ error: "bad to address" }, 400);
        }
        if (message.length > 140) {
            return json({ error: "message > 140 chars" }, 400);
        }

        const certs = parsePem(pem);
        if (certs.length < 2) return json({ error: "parsed < 2 certs" }, 400);

        const provider = new JsonRpcProvider(env.RPC_URL);
        const chainId = Number((await provider.getNetwork()).chainId);
        const faucetAddr = getAddress(env.FAUCET_ADDRESS);
        const toAddr = getAddress(to);

        // SYBIL PRE-CHECK: keccak256(certs[1]) is the per-device StrongBox
        // attestation-key fingerprint. If this fingerprint already claimed,
        // return the original Tagged event without spending gas / a verify
        // RPC call / a doomed claim tx that the contract would revert anyway.
        const deviceFingerprint = keccak256(certs[1]);
        const faucetView = new Contract(faucetAddr, FAUCET_ABI, provider);
        if (await faucetView.claimed(deviceFingerprint)) {
            let originalTagged = null;
            try {
                // Base Sepolia RPC limits eth_getLogs to 2000 blocks/call.
                // Walk back in 1900-block chunks until we find the Tagged event
                // (or hit the configured deploy block).
                const fromFloor = Number(env.FAUCET_DEPLOY_BLOCK ?? 0);
                const head = await provider.getBlockNumber();
                const STEP = 1900;
                for (let to = head; to >= fromFloor; to -= STEP) {
                    const from = Math.max(fromFloor, to - STEP + 1);
                    const evs = await faucetView.queryFilter(
                        faucetView.filters.Tagged(deviceFingerprint), from, to,
                    );
                    if (evs.length) {
                        const e = evs[0];
                        originalTagged = {
                            txHash: e.transactionHash,
                            to: e.args.to,
                            message: e.args.message,
                            timestamp: Number(e.args.timestamp),
                            explorer: `https://sepolia.basescan.org/tx/${e.transactionHash}`,
                        };
                        break;
                    }
                    if (from === fromFloor) break;
                }
            } catch (_) {}
            return json({
                alreadyClaimed: true,
                deviceFingerprint,
                faucet: faucetAddr,
                original: originalTagged,
            }, 200);
        }

        const expectedChallenge = await computeBinding(chainId, faucetAddr, toAddr, message);

        const coder = AbiCoder.defaultAbiCoder();
        const proof = coder.encode(
            ["tuple(bytes[] certs, bytes challenge)"],
            [{ certs, challenge: expectedChallenge }],
        );

        const verifier = new Contract(env.VERIFIER_ADDRESS, VERIFIER_ABI, provider);
        let codeId, _pubkey, userData;
        try {
            [codeId, _pubkey, userData] = await verifier.verify(proof);
        } catch (e) {
            return json({ error: `verify() reverted: ${e.shortMessage || e.message}` }, 422);
        }

        if (userData.toLowerCase() !== expectedChallenge.toLowerCase()) {
            return json({
                error: "challenge in leaf does not match the recomputed binding",
                verifierUserData: userData,
                expected: expectedChallenge,
            }, 422);
        }

        const pemHash = keccak256(toUtf8Bytes(pem));
        const deadline = BigInt(Math.floor(Date.now() / 1000) + PERMIT_TTL_SECONDS);

        const wallet = new Wallet(env.RELAYER_KEY, provider);

        const digest = keccak256(coder.encode(
            ["uint256", "address", "string", "bytes32", "address", "bytes32", "bytes32", "bytes32", "uint256"],
            [chainId, faucetAddr, DOMAIN, deviceFingerprint, toAddr, keccak256(toUtf8Bytes(message)), pemHash, codeId, deadline],
        ));
        const sig = await wallet.signMessage(getBytes(digest));

        const faucet = new Contract(faucetAddr, FAUCET_ABI, wallet);
        let tx;
        try {
            tx = await faucet.claim(
                deviceFingerprint, toAddr, message, pemHash, codeId, deadline, sig,
            );
        } catch (e) {
            return json({
                error: `claim() reverted: ${e.shortMessage || e.message}`,
                deviceFingerprint, codeId,
            }, 500);
        }

        return json({
            txHash: tx.hash,
            explorer: `https://sepolia.basescan.org/tx/${tx.hash}`,
            deviceFingerprint,
            codeId,
            pemHash,
            faucet: faucetAddr,
            relayer: wallet.address,
            domain: DOMAIN,
        });
    },
};
