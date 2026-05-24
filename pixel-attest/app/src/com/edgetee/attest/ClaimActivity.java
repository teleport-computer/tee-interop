package com.edgetee.attest;

import android.app.Activity;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Base64;

/**
 * Pixel faucet "tag" activity.
 *
 * Generates a fresh attested StrongBox key whose attestationChallenge binds
 * (chainId, faucetAddress, toAddress, sha256(message)) via:
 *   binding = SHA256("pixel-faucet/v1" || chainId_be8 || faucet || to || sha256(message))
 *
 * Then POSTs the resulting cert chain + claim parameters to a Cloudflare
 * Worker relayer which view-calls the on-chain verifier, signs a claim
 * permit, and submits faucet.claim() to PixelFaucet. The activity writes
 * the worker's response (tx hash + explorer URL) to claim_result.json.
 *
 * Invoke from host:
 *   adb shell am start -n com.edgetee.attest/.ClaimActivity \
 *     -e to "0xYourWalletAddress" \
 *     -e message "hi from my pixel" \
 *     -e chain_id 84532 \
 *     -e faucet "0xPixelFaucetAddress" \
 *     -e relayer "https://pixel-faucet-relayer.workers.dev/"
 *   adb pull /sdcard/Android/data/com.edgetee.attest/files/claim_result.json
 */
public class ClaimActivity extends Activity {
    private static final String TAG = "EdgeTeeClaim";
    private static final String DOMAIN = "pixel-faucet/v1";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        File outDir = getExternalFilesDir(null);
        File resultFile = new File(outDir, "claim_result.json");

        JSONObject result = new JSONObject();
        try {
            String to = required("to");
            String message = getIntent().getStringExtra("message");
            if (message == null) message = "";
            long chainId = Long.parseLong(required("chain_id"));
            String faucet = required("faucet");
            String relayerUrl = required("relayer");

            if (!to.matches("^0x[0-9a-fA-F]{40}$")) throw new IllegalArgumentException("bad to");
            if (!faucet.matches("^0x[0-9a-fA-F]{40}$")) throw new IllegalArgumentException("bad faucet");
            if (message.length() > 140) throw new IllegalArgumentException("message > 140 chars");

            byte[] binding = computeBinding(chainId, faucet, to, message);
            String alias = "pixel-faucet-" + System.currentTimeMillis();

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(alias)) ks.deleteEntry(alias);

            int purposes = KeyProperties.PURPOSE_SIGN
                         | KeyProperties.PURPOSE_VERIFY
                         | KeyProperties.PURPOSE_AGREE_KEY;
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, purposes)
                    .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(binding)
                    .setIsStrongBoxBacked(true);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(builder.build());
            kpg.generateKeyPair();

            Certificate[] chain = ks.getCertificateChain(alias);
            String pem = encodePem(chain);

            JSONObject body = new JSONObject();
            body.put("pem", pem);
            body.put("to", to);
            body.put("message", message);

            HttpResponse resp = postJson(relayerUrl, body.toString());
            Log.i(TAG, "relayer status=" + resp.code + " len=" + resp.body.length());

            result.put("status", resp.code == 200 ? "OK" : "RELAYER_ERROR");
            result.put("http_status", resp.code);
            result.put("alias", alias);
            result.put("challenge_hex", toHex(binding));
            result.put("relayer_response", new JSONObject(resp.body));
        } catch (Exception e) {
            Log.e(TAG, "claim failed", e);
            try {
                result.put("status", "ERROR");
                result.put("error_class", e.getClass().getName());
                result.put("error_message", String.valueOf(e.getMessage()));
            } catch (Exception ignored) {}
        }

        try (FileOutputStream fos = new FileOutputStream(resultFile)) {
            fos.write(result.toString(2).getBytes("UTF-8"));
        } catch (Exception ignored) {}
        finish();
    }

    private String required(String key) {
        String v = getIntent().getStringExtra(key);
        if (v == null) throw new IllegalArgumentException("missing -e " + key);
        return v;
    }

    private static byte[] computeBinding(long chainId, String faucetHex, String toHex, String message) throws Exception {
        byte[] domain = DOMAIN.getBytes("UTF-8");
        byte[] chainIdBytes = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(chainId).array();
        byte[] faucet = hexToBytes(faucetHex);
        byte[] to = hexToBytes(toHex);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] msgHash = sha.digest(message.getBytes("UTF-8"));

        sha.reset();
        sha.update(domain);
        sha.update(chainIdBytes);
        sha.update(faucet);
        sha.update(to);
        sha.update(msgHash);
        return sha.digest();
    }

    private static String encodePem(Certificate[] chain) throws Exception {
        StringBuilder sb = new StringBuilder();
        Base64.Encoder enc = Base64.getMimeEncoder(64, "\n".getBytes("UTF-8"));
        for (Certificate c : chain) {
            sb.append("-----BEGIN CERTIFICATE-----\n");
            sb.append(enc.encodeToString(c.getEncoded()));
            sb.append("\n-----END CERTIFICATE-----\n");
        }
        return sb.toString();
    }

    private static class HttpResponse {
        int code; String body;
    }

    private static HttpResponse postJson(String urlStr, String body) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(60000);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes("UTF-8"));
        }
        HttpResponse out = new HttpResponse();
        out.code = conn.getResponseCode();
        java.io.InputStream is = (out.code >= 200 && out.code < 300)
                ? conn.getInputStream()
                : conn.getErrorStream();
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        if (is != null) {
            byte[] tmp = new byte[4096];
            int n;
            while ((n = is.read(tmp)) > 0) buf.write(tmp, 0, n);
        }
        out.body = buf.toString("UTF-8");
        if (out.body.isEmpty()) out.body = "{}";
        return out;
    }

    private static byte[] hexToBytes(String s) {
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return "0x" + sb.toString();
    }
}
