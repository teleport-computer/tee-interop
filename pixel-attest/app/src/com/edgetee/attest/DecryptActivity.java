package com.edgetee.attest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pixel-side counterpart to tools/android_keyattest/encrypt_to_attested.py.
 *
 * Invoke from host:
 *   adb push bundle.json /sdcard/Android/data/com.edgetee.attest/files/in.json
 *   adb shell am start -n com.edgetee.attest/.DecryptActivity \
 *     -e bundle_path /sdcard/Android/data/com.edgetee.attest/files/in.json \
 *     -e alias "edgetee-1"
 *   adb pull /sdcard/Android/data/com.edgetee.attest/files/decrypt_result.json
 *
 * Reads the GHA-emitted pairing bundle, ECDH-AGREEs with the StrongBox key
 * under `alias`, HKDF-SHA256-derives an AES-256-GCM key, decrypts, hashes
 * the plaintext, and reports whether it matches plaintext_sha256_hex.
 *
 * The plaintext bytes themselves are *not* written out — only their SHA-256.
 * That keeps the public commitment the only thing leaving the device.
 */
public class DecryptActivity extends Activity {
    private static final String TAG = "EdgeTeeDecrypt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String bundlePath = getIntent().getStringExtra("bundle_path");
        String alias = getIntent().getStringExtra("alias");
        if (alias == null) alias = "edgetee_attest_key";

        File outDir = getExternalFilesDir(null);
        File outFile = new File(outDir, "decrypt_result.json");

        JSONObject result = new JSONObject();
        try {
            if (bundlePath == null) throw new IllegalArgumentException("missing -e bundle_path");

            JSONObject in = readJson(new File(bundlePath));

            byte[] ephemeralSpki = unhex(in.getString("ephemeral_pubkey_spki_hex"));
            byte[] nonce         = unhex(in.getString("nonce_hex"));
            byte[] ciphertext    = unhex(in.getString("ciphertext_hex"));
            byte[] expectedHash  = unhex(in.getString("plaintext_sha256_hex"));
            String kdfInfoUtf8   = in.getString("kdf_info_utf8");
            int expectedLen      = in.getInt("plaintext_len");

            PublicKey ephemeral = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(ephemeralSpki));

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            PrivateKey priv = (PrivateKey) ks.getKey(alias, null);
            if (priv == null) throw new IllegalStateException("no key under alias " + alias);

            KeyAgreement ka = KeyAgreement.getInstance("ECDH", "AndroidKeyStore");
            ka.init(priv);
            ka.doPhase(ephemeral, true);
            byte[] shared = ka.generateSecret();

            byte[] aesKey = hkdfSha256(shared, null, kdfInfoUtf8.getBytes("UTF-8"), 32);

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                   new GCMParameterSpec(128, nonce));
            byte[] plaintext = c.doFinal(ciphertext);

            byte[] gotHash = MessageDigest.getInstance("SHA-256").digest(plaintext);
            boolean match = constTimeEq(gotHash, expectedHash) && plaintext.length == expectedLen;

            result.put("status", "OK");
            result.put("alias", alias);
            result.put("plaintext_len", plaintext.length);
            result.put("recovered_plaintext_sha256_hex", "0x" + hex(gotHash));
            result.put("expected_plaintext_sha256_hex", in.getString("plaintext_sha256_hex"));
            result.put("match", match);
            if (in.has("context")) result.put("context", in.getJSONObject("context"));
            Log.i(TAG, "match=" + match + " sha256=" + hex(gotHash));
        } catch (Exception e) {
            Log.e(TAG, "decrypt failed", e);
            try {
                result.put("status", "ERROR");
                result.put("error_class", e.getClass().getName());
                result.put("error_message", String.valueOf(e.getMessage()));
            } catch (Exception ignored) {}
        }

        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            fos.write(result.toString(2).getBytes("UTF-8"));
        } catch (Exception ignored) {}
        finish();
    }

    private static JSONObject readJson(File f) throws Exception {
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] buf = new byte[(int) f.length()];
            int off = 0;
            while (off < buf.length) {
                int n = fis.read(buf, off, buf.length - off);
                if (n < 0) break;
                off += n;
            }
            return new JSONObject(new String(buf, 0, off, "UTF-8"));
        }
    }

    // RFC 5869 HKDF-SHA256. salt=null means a 32-byte zero salt.
    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        if (salt == null) salt = new byte[32];
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int pos = 0, counter = 1;
        while (pos < length) {
            mac.reset();
            mac.update(t);
            mac.update(info);
            mac.update((byte) counter);
            t = mac.doFinal();
            int take = Math.min(t.length, length - pos);
            System.arraycopy(t, 0, out, pos, take);
            pos += take;
            counter++;
        }
        return out;
    }

    private static byte[] unhex(String s) {
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        int n = s.length() / 2;
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    private static boolean constTimeEq(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }
}
