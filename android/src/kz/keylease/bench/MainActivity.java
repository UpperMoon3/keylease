package kz.keylease.bench;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Measures the Android Keystore operations that KeyLease performs on a
 * device: ECDSA P-256 signing of custody requests (AFU class and
 * user-authentication-bound "presence" class), AES-256-GCM sealing and
 * opening of the 32-byte device factor, key generation and key attestation,
 * in the TEE and, where available, in StrongBox. Results go to logcat
 * (tag KLBENCH) and to files/keystore_bench.json.
 */
public class MainActivity extends Activity {
    static final String TAG = "KLBENCH";
    static final int WARM = 5, N = 50, NGEN = 10;
    final StringBuilder json = new StringBuilder();
    TextView view;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        view = new TextView(this);
        view.setTextSize(11);
        ScrollView sv = new ScrollView(this);
        sv.addView(view);
        setContentView(sv);
        new Thread(this::runAll).start();
    }

    void out(String s) {
        Log.i(TAG, s);
        runOnUiThread(() -> view.append(s + "\n"));
    }

    interface Op { void run() throws Exception; }

    static double[] time(Op op, int warm, int n) throws Exception {
        for (int i = 0; i < warm; i++) op.run();
        double[] t = new double[n];
        for (int i = 0; i < n; i++) {
            long s = System.nanoTime();
            op.run();
            t[i] = (System.nanoTime() - s) / 1e6;
        }
        return t;
    }

    static double q(double[] a, double p) {
        double[] s = a.clone();
        Arrays.sort(s);
        double idx = p * (s.length - 1);
        int lo = (int) Math.floor(idx), hi = (int) Math.ceil(idx);
        return s[lo] + (s[hi] - s[lo]) * (idx - lo);
    }

    void record(String name, double[] t) {
        String line = String.format(Locale.US,
                "{\"op\":\"%s\",\"n\":%d,\"median_ms\":%.3f,\"q1_ms\":%.3f,"
                        + "\"q3_ms\":%.3f,\"p5_ms\":%.3f,\"p95_ms\":%.3f}",
                name, t.length, q(t, .5), q(t, .25), q(t, .75), q(t, .05), q(t, .95));
        if (json.length() > 0) json.append(",\n");
        json.append(line);
        out(line);
    }

    void note(String key, String value) {
        if (json.length() > 0) json.append(",\n");
        json.append(String.format("{\"note\":\"%s\",\"value\":\"%s\"}", key,
                value.replace("\"", "'")));
        out(key + " = " + value);
    }

    static String level(KeyInfo ki) {
        if (Build.VERSION.SDK_INT >= 31) {
            switch (ki.getSecurityLevel()) {
                case KeyProperties.SECURITY_LEVEL_STRONGBOX: return "StrongBox";
                case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return "TEE";
                case KeyProperties.SECURITY_LEVEL_SOFTWARE: return "software";
                default: return "unknown(" + ki.getSecurityLevel() + ")";
            }
        }
        return ki.isInsideSecureHardware() ? "secure hardware" : "software";
    }

    KeyPair genEc(String alias, boolean strongbox, boolean authBound,
                  byte[] challenge) throws Exception {
        KeyGenParameterSpec.Builder sb = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256);
        if (strongbox) sb.setIsStrongBoxBacked(true);
        if (authBound) {
            sb.setUserAuthenticationRequired(true);
            sb.setUserAuthenticationParameters(300,
                    KeyProperties.AUTH_DEVICE_CREDENTIAL
                            | KeyProperties.AUTH_BIOMETRIC_STRONG);
        }
        if (challenge != null) sb.setAttestationChallenge(challenge);
        KeyPairGenerator g = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        g.initialize(sb.build());
        return g.generateKeyPair();
    }

    SecretKey genAes(String alias, boolean strongbox) throws Exception {
        KeyGenParameterSpec.Builder sb = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256);
        if (strongbox) sb.setIsStrongBoxBacked(true);
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore");
        g.init(sb.build());
        return g.generateKey();
    }

    void backend(String tag, boolean sb) throws Exception {
        final byte[] msg = new byte[200];
        new SecureRandom().nextBytes(msg);
        // key generation
        final int[] k = {0};
        record(tag + " ECDSA P-256 keygen", time(() ->
                genEc("gen-" + tag + "-" + (k[0]++), sb, false, null), 1, NGEN));
        KeyPair kp = genEc("auth-" + tag, sb, false, null);
        KeyFactory kf = KeyFactory.getInstance(kp.getPrivate().getAlgorithm(),
                "AndroidKeyStore");
        note(tag + " EC key security level",
                level(kf.getKeySpec(kp.getPrivate(), KeyInfo.class)));
        final PrivateKey priv = kp.getPrivate();
        final PublicKey pub = kp.getPublic();
        final byte[][] sig = new byte[1][];
        record(tag + " ECDSA P-256 sign (AFU class)", time(() -> {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(priv);
            s.update(msg);
            sig[0] = s.sign();
        }, WARM, N));
        record(tag + " ECDSA P-256 verify (software)", time(() -> {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(pub);
            s.update(msg);
            if (!s.verify(sig[0])) throw new IllegalStateException("verify");
        }, WARM, N));
        // AES-256-GCM sealing of the 32-byte device factor
        record(tag + " AES-256 keygen", time(() ->
                genAes("aesgen-" + tag + "-" + (k[0]++), sb), 1, NGEN));
        final SecretKey aes = genAes("seal-" + tag, sb);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(aes.getAlgorithm(),
                "AndroidKeyStore");
        note(tag + " AES key security level",
                level((KeyInfo) skf.getKeySpec(aes, KeyInfo.class)));
        final byte[] kdev = new byte[32];
        new SecureRandom().nextBytes(kdev);
        final byte[][] ct = new byte[2][];
        record(tag + " AES-256-GCM seal K_dev (32 B)", time(() -> {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, aes);
            ct[0] = c.getIV();
            ct[1] = c.doFinal(kdev);
        }, WARM, N));
        record(tag + " AES-256-GCM open K_dev (32 B)", time(() -> {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, aes, new GCMParameterSpec(128, ct[0]));
            byte[] p = c.doFinal(ct[1]);
            if (!Arrays.equals(p, kdev)) throw new IllegalStateException("open");
        }, WARM, N));
        // key attestation (A5): generation with a challenge and chain length
        final byte[] chal = new byte[32];
        new SecureRandom().nextBytes(chal);
        record(tag + " ECDSA P-256 keygen with attestation", time(() ->
                genEc("att-" + tag + "-" + (k[0]++), sb, false, chal), 1, NGEN));
        genEc("att-" + tag, sb, false, chal);
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Certificate[] chain = ks.getCertificateChain("att-" + tag);
        note(tag + " attestation chain length", String.valueOf(chain.length));
        // presence class: user-authentication-bound key (300 s window)
        KeyguardManager km = getSystemService(KeyguardManager.class);
        if (km.isDeviceSecure()) {
            KeyPair pk = genEc("pres-" + tag, sb, true, null);
            final PrivateKey ppriv = pk.getPrivate();
            note(tag + " presence key security level", level(
                    kf.getKeySpec(ppriv, KeyInfo.class)));
            try {
                record(tag + " ECDSA P-256 sign (presence class)", time(() -> {
                    Signature s = Signature.getInstance("SHA256withECDSA");
                    s.initSign(ppriv);
                    s.update(msg);
                    s.sign();
                }, WARM, N));
            } catch (UserNotAuthenticatedException e) {
                note(tag + " presence key use", "UserNotAuthenticatedException "
                        + "(device not unlocked within the 300 s window)");
            }
        } else {
            note(tag + " presence key", "skipped: no secure lock screen");
        }
    }

    void ed25519() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            g.initialize(new KeyGenParameterSpec.Builder("ed",
                    KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("ed25519"))
                    .setDigests(KeyProperties.DIGEST_NONE).build());
            final KeyPair kp = g.generateKeyPair();
            final byte[] msg = new byte[200];
            record("TEE Ed25519 sign", time(() -> {
                Signature s = Signature.getInstance("Ed25519");
                s.initSign(kp.getPrivate());
                s.update(msg);
                s.sign();
            }, WARM, N));
        } catch (Throwable t) {
            note("Ed25519 in AndroidKeyStore", "unsupported: " + t.getClass()
                    .getSimpleName() + ": " + t.getMessage());
        }
    }

    void runAll() {
        try {
            note("device", Build.MANUFACTURER + " " + Build.MODEL + " ("
                    + Build.DEVICE + ")");
            note("android", Build.VERSION.RELEASE + " / API " + Build.VERSION.SDK_INT);
            if (Build.VERSION.SDK_INT >= 31) note("soc", Build.SOC_MANUFACTURER
                    + " " + Build.SOC_MODEL);
            boolean hasSb = getPackageManager().hasSystemFeature(
                    PackageManager.FEATURE_STRONGBOX_KEYSTORE);
            note("strongbox feature", String.valueOf(hasSb));
            note("secure lock screen", String.valueOf(
                    getSystemService(KeyguardManager.class).isDeviceSecure()));
            backend("TEE", false);
            if (hasSb) {
                try {
                    backend("StrongBox", true);
                } catch (Throwable t) {
                    note("StrongBox", "failed: " + t);
                }
            }
            ed25519();
            File f = new File(getFilesDir(), "keystore_bench.json");
            try (FileOutputStream o = new FileOutputStream(f)) {
                o.write(("[\n" + json + "\n]\n").getBytes(StandardCharsets.UTF_8));
            }
            out("DONE " + f.getAbsolutePath());
        } catch (Throwable t) {
            out("ERROR " + Log.getStackTraceString(t));
        }
    }
}
