package com.rai.encryption.utils;

import com.rai.encryption.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

public class EncryptionUtils {
    // used
    /**
     *
     * @return
     */
    public static File kekFolder() {
        return new File(EncryptionConstants.MAIN_FOLDER);
    }
    // used
    /**
     *
     * @return
     */
    public static IvParameterSpec generateIv() {
        System.out.println(String.format("Generate Initialisation Vector"));
        byte[] iv = { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        return ivspec;

    }

    // used
    public static SecretKey generateSecretKey(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        System.out.println(String.format("Generate SecretKey using '%s' password & '%s' Salt", password, salt));

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
        return secret;

    }
    // used
    public static String generatePrng(){
        return KeyProvider.getRandomAlphanumericString(100);
    }

    // used
    public static String encrypt(String plainString, SecretKey secretKey, IvParameterSpec iv)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException,
            InvalidAlgorithmParameterException {

        System.out.println(String.format("Encrypting '%s' using '%s' Secretkey", plainString, secretKey));

        Cipher cipher = Cipher.getInstance(EncryptionConstants.ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] cipherText = cipher.doFinal(plainString.getBytes());
        return getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String encryptedString, SecretKey secretKey, IvParameterSpec iv)
            throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException,
            InvalidAlgorithmParameterException {

        System.out.println(String.format("Decrypting '%s' using '%s' as SecretKey", encryptedString, secretKey));

        Cipher cipher = Cipher.getInstance(EncryptionConstants.ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] plainText = cipher.doFinal(getDecoder().decode(encryptedString));

        return new String(plainText);
    }
}
