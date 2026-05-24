package com.edgetee.attest;

import android.app.Activity;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Base64;

/**
 * Minimal Android Key Attestation generator.
 *
 * Invoke from host:
 *   adb shell am start -n com.edgetee.attest/.MainActivity \
 *     -e challenge "deadbeefcafe"  -e alias "edgetee-1"  -e strongbox "true"
 *   adb pull /sdcard/Android/data/com.edgetee.attest/files/attestation.pem
 *
 * Output PEM: full cert chain from the leaf (with attestation extension)
 * up to a Google-rooted intermediate.
 */
public class MainActivity extends Activity {
    private static final String TAG = "EdgeTeeAttest";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String challengeStr = getIntent().getStringExtra("challenge");
        if (challengeStr == null) challengeStr = "edge-tee-default-challenge";
        byte[] challenge = challengeStr.getBytes();

        String alias = getIntent().getStringExtra("alias");
        if (alias == null) alias = "edgetee_attest_key";

        boolean strongBox = "true".equalsIgnoreCase(getIntent().getStringExtra("strongbox"));

        try {
            // Remove any pre-existing key under this alias so each invocation is fresh
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(alias)) ks.deleteEntry(alias);

            // AGREE_KEY is required for ECDH-based pairing (DecryptActivity).
            // PURPOSE_AGREE_KEY landed in API 31; Pixel 6 ships >= Android 12.
            int purposes = KeyProperties.PURPOSE_SIGN
                         | KeyProperties.PURPOSE_VERIFY
                         | KeyProperties.PURPOSE_AGREE_KEY;
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, purposes)
                    .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge);

            if (strongBox) builder.setIsStrongBoxBacked(true);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(builder.build());
            kpg.generateKeyPair();

            Certificate[] chain = ks.getCertificateChain(alias);
            Log.i(TAG, "got chain length=" + chain.length + " for alias=" + alias);

            File outDir = getExternalFilesDir(null);
            File pem = new File(outDir, "attestation.pem");
            try (FileOutputStream fos = new FileOutputStream(pem)) {
                for (Certificate c : chain) {
                    byte[] der = c.getEncoded();
                    String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
                    fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
                    fos.write(b64.getBytes());
                    fos.write("\n-----END CERTIFICATE-----\n".getBytes());
                }
            }
            File info = new File(outDir, "attestation.info");
            try (FileOutputStream fos = new FileOutputStream(info)) {
                fos.write(("challenge=" + challengeStr + "\n").getBytes());
                fos.write(("alias=" + alias + "\n").getBytes());
                fos.write(("strongbox=" + strongBox + "\n").getBytes());
                fos.write(("chain_length=" + chain.length + "\n").getBytes());
                fos.write(("status=OK\n").getBytes());
            }
            Log.i(TAG, "wrote " + pem.getAbsolutePath());
        } catch (Exception e) {
            Log.e(TAG, "attestation failed: " + e.getMessage(), e);
            try {
                File outDir = getExternalFilesDir(null);
                File err = new File(outDir, "attestation.err");
                try (FileOutputStream fos = new FileOutputStream(err)) {
                    fos.write((e.getClass().getName() + ": " + e.getMessage() + "\n").getBytes());
                    for (StackTraceElement s : e.getStackTrace()) {
                        fos.write(("  at " + s.toString() + "\n").getBytes());
                    }
                }
            } catch (Exception ignored) {}
        }
        finish();
    }
}
