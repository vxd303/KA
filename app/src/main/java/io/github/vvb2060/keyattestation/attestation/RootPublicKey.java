package io.github.vvb2060.keyattestation.attestation;

import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import io.github.vvb2060.keyattestation.AppApplication;

public class RootPublicKey {
    public enum TestKey {
        NONE,
        RSA2048,
        RSA4096,
        RSA8192,
    }
    public enum Status {
        NULL,
        FAILED,
        UNKNOWN,
        AOSP,
        GOOGLE,
        GOOGLE_RKP,
        KNOX,
        OEM,
    }

    private static final String GOOGLE_ROOT_PUBLIC_KEY = """
            MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU\
            FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j\
            lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y\
            //0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X\
            pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI\
            mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB\
            +TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q\
            uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp\
            Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7\
            gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82\
            ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+\
            NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==""";

    private static final String AOSP_ROOT_EC_PUBLIC_KEY = """
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu\
            D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA==""";

    private static final String AOSP_ROOT_RSA_PUBLIC_KEY = """
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf\
            d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg\
            MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm\
            +Vfkl5YLCazOkjWFmwIDAQAB""";

    private static final String KNOX_SAKV1_ROOT_PUBLIC_KEY = """
            MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBs9Qjr//REhkXW7jUqjY9KNwWac4r\
            5+kdUGk+TZjRo1YEa47Axwj6AJsbOjo4QsHiYRiWTELvFeiuBsKqyuF0xyAAKvDo\
            fBqrEq1/Ckxo2mz7Q4NQes3g4ahSjtgUSh0k85fYwwHjCeLyZ5kEqgHG9OpOH526\
            FFAK3slSUgC8RObbxys=""";

    private static final String KNOX_SAKV2_ROOT_PUBLIC_KEY = """
            MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA\
            46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd12\
            4n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBo\
            ZsapxB0gAOs0jSPRX5M=""";

    private static final String KNOX_SAKMV1_ROOT_PUBLIC_KEY = """
            MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB9XeEN8lg6p5xvMVWG42P2Qi/aRKX\
            2rPRNgK92UlO9O/TIFCKHC1AWCLFitPVEow5W+yEgC2wOiYxgepY85TOoH0AuEkL\
            oiC6ldbF2uNVU3rYYSytWAJg3GFKd1l9VLDmxox58Hyw2Jmdd5VSObGiTFQ/SgKs\
            n2fbQPtpGlNxgEfd6Y8=""";

    private static final byte[] googleKey = Base64.decode(GOOGLE_ROOT_PUBLIC_KEY, 0);
    private static final byte[] aospEcKey = Base64.decode(AOSP_ROOT_EC_PUBLIC_KEY, 0);
    private static final byte[] aospRsaKey = Base64.decode(AOSP_ROOT_RSA_PUBLIC_KEY, 0);
    private static final byte[] knoxSakv1Key = Base64.decode(KNOX_SAKV1_ROOT_PUBLIC_KEY, 0);
    private static final byte[] knoxSakv2Key = Base64.decode(KNOX_SAKV2_ROOT_PUBLIC_KEY, 0);
    private static final byte[] knoxSakmv1Key = Base64.decode(KNOX_SAKMV1_ROOT_PUBLIC_KEY, 0);
    private static final Set<PublicKey> oemKeys = getOemPublicKey();

    private static Set<PublicKey> getOemPublicKey() {
        var resName = "android:array/vendor_required_attestation_certificates";
        var res = AppApplication.app.getResources();
        // noinspection DiscouragedApi
        var id = res.getIdentifier(resName, null, null);
        if (id == 0) {
            return null;
        }
        var set = new HashSet<PublicKey>();
        try {
            var cf = CertificateFactory.getInstance("X.509");
            for (var s : res.getStringArray(id)) {
                var cert = s.replaceAll("\\s+", "\n")
                        .replaceAll("-BEGIN\\nCERTIFICATE-", "-BEGIN CERTIFICATE-")
                        .replaceAll("-END\\nCERTIFICATE-", "-END CERTIFICATE-");
                var input = new ByteArrayInputStream(cert.getBytes());
                var publicKey = cf.generateCertificate(input).getPublicKey();
                set.add(publicKey);
            }
        } catch (CertificateException e) {
            Log.e(AppApplication.TAG, "getOemKeys: ", e);
            return null;
        }
        set.removeIf(key -> Arrays.equals(key.getEncoded(), googleKey));
        if (set.isEmpty()) {
            return null;
        }
        set.forEach(key -> Log.i(AppApplication.TAG, "getOemKeys: " + key));
        return set;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Detect if verifiedBootKey matches known AVB test public keys by SHA-256 digest.
     */
    public static TestKey checkVbmetaTestKeyBySha256(byte[] verifiedBootKey) {
        if (verifiedBootKey == null) return TestKey.NONE;

        // Known SHA-256 fingerprints for AVB test keys
        final String SHA256_RSA2048 = "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c";
        final String SHA256_RSA4096 = "7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6";
        final String SHA256_RSA8192 = "e15e2365469ce672a91d02cc8d9c2f29b787481e574d3b56ac774153d7ced614";

        var sha256_2048 = hexToBytes(SHA256_RSA2048);
        var sha256_4096 = hexToBytes(SHA256_RSA4096);
        var sha256_8192 = hexToBytes(SHA256_RSA8192);

        if (Arrays.equals(verifiedBootKey, sha256_2048)) return TestKey.RSA2048;
        if (Arrays.equals(verifiedBootKey, sha256_4096)) return TestKey.RSA4096;
        if (Arrays.equals(verifiedBootKey, sha256_8192)) return TestKey.RSA8192;

        return TestKey.NONE;
    }

    public static Status check(byte[] publicKey) {
        if (Arrays.equals(publicKey, googleKey)) {
            return Status.GOOGLE;
        } else if (Arrays.equals(publicKey, aospEcKey)) {
            return Status.AOSP;
        } else if (Arrays.equals(publicKey, aospRsaKey)) {
            return Status.AOSP;
        } else if (Arrays.equals(publicKey, knoxSakv2Key)) {
            return Status.KNOX;
        } else if (Arrays.equals(publicKey, knoxSakv1Key)) {
            return Status.KNOX;
        } else if (Arrays.equals(publicKey, knoxSakmv1Key)) {
            return Status.KNOX;
        } else if (oemKeys != null) {
            for (var key : oemKeys) {
                if (Arrays.equals(publicKey, key.getEncoded())) {
                    return Status.OEM;
                }
            }
        }
        return Status.UNKNOWN;
    }
}
