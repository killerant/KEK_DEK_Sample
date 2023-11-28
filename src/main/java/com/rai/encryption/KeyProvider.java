package com.rai.encryption;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * SideKEK security provider.
 *
 * Supports storing encryption keys in the filesystem metadata to prevent exfiltration via Path Traversal, XXE, LFI,
 * and other similar vulnerabilities
 *
 * @author Dmitriy Beryoza
 * @author Ron Craig
 */
public class KeyProvider extends Provider {

    private static final long serialVersionUID = -2505740712906556017L;

    public KeyProvider() {
        super("SideKEK", 1.0, "SideKEK security provider");

        // Register keystore providers
      //  put("KeyStore." + TIMESTAMP_KEYSTORE,     TimestampKeyStoreSpi.class.getCanonicalName());
        put("KeyStore." + SECRET_FOLDER_KEYSTORE, SecretFolderKeyStoreSpi.class.getCanonicalName());
    }

  //  public static final String TIMESTAMP_KEYSTORE = "TimestampKeyStore";
    public static final String SECRET_FOLDER_KEYSTORE = "SecretFolderKeyStore";

    private static SecureRandom srng = null;
    // used
    /**
     * Generates random alphanumeric string of defined length that is safe to use in file names.
     *
     * @param length Length of the string to generate.
     * @return Generated random string.
     */
    public static String getRandomAlphanumericString(int length) {
        if (length <= 0) {
            return "";
        }

        // TODO request fewer bytes
        byte[] bytes = getRandomBytes(length);

        // Generate unique name from alphabet [-_a-zA-Z0-9]
        byte[] encodedBytes = Base64.getUrlEncoder().withoutPadding().encode(bytes);

        return new String(encodedBytes, 0, length);
    }
    // used
    /**
     * Generate specified number of random bytes.
     *
     * @param numBytes Number of bytes to generate.
     * @return Random bytes.
     */
    private static byte[] getRandomBytes(int numBytes) {
        if (srng == null) {
            srng = new SecureRandom();
        }

        byte[] bytes = new byte[numBytes];
        srng.nextBytes(bytes);
        return bytes;
    }
}