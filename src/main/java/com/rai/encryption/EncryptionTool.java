package com.rai.encryption;

import com.rai.encryption.utils.EncryptionUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.security.Security;

public class EncryptionTool {
    static final String ENCRYPT = "ENCRYPT";
    static final String DECRYPT = "DECRYPT";

    /**
     *
     * @param args
     *         --> [mode, password, masterKey, salt]
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        String mode = args[0].toUpperCase();
        String password = args[1]; // [Decrypt Mode] will hold the encrypted Password
        String masterKey = args[2];// [Decrypt Mode] will hold the encrypted PRNG
        String salt = args[3];

        Security.addProvider(new KeyProvider());
        SecureKeystore keyStore = new SecureKeystore(EncryptionUtils.kekFolder());

        // Generate Initialisation Vector
        IvParameterSpec iv = EncryptionUtils.generateIv();

        if (ENCRYPT.equals(mode))  {
            // Create directory
            new File(EncryptionUtils.kekFolder() + "/" + EncryptionConstants.KEYSTORE_SUBFOLDER).mkdirs();
            // Generate KEK
            System.out.println("------------------------------------\n");
            SecretKey kekKey = EncryptionUtils.generateSecretKey(masterKey,salt);
            System.out.println(String.format("Generated KEK ---> %s",kekKey));
            // Save to KeyStore
            keyStore.storeKek(kekKey, EncryptionConstants.KEK_ENTRY_ALIAS);

            // Retrieve KEK from the KeyStore - just to validate if KEK was saved
            SecretKey kekFromKS = keyStore.retrieveKek();
            System.out.println(String.format("KEK from KeyStore is ---> %s",kekFromKS));

            // Generate PRNG
            System.out.println("------------------------------------\n");
            String prng = EncryptionUtils.generatePrng();
            System.out.println(String.format("PRNG generated is ---> %s",prng));

            // Generate DEK using PRNG
            SecretKey dekKey = EncryptionUtils.generateSecretKey(prng,salt);
            System.out.println(String.format("Generated DEK ---> %s",dekKey));

            // Encrypt password - will try to encrypt DB password
            System.out.println("------------------------------------\n");
            System.out.println("Encrypt the database password!");
            String encryptedPassword = EncryptionUtils.encrypt(password,dekKey, iv);
            System.out.println(String.format("Encrypted password is ---> %s",encryptedPassword));

            // Encrypt the PRNG
            System.out.println("------------------------------------\n");
            System.out.println("Encrypt the PRNG!");
            String encryptedPRNG = EncryptionUtils.encrypt(prng,kekKey, iv);
            System.out.println(String.format("Encrypted PRNG is ---> %s", encryptedPRNG));

        } else if (DECRYPT.equals(mode)) {

            // Retrieve KEK
            System.out.println("------------------------------------\n");
            System.out.println("Retrieving KEK...");
            SecretKey kekKeyFromKeystore = keyStore.retrieveKek();
            System.out.println(String.format("KEK from KeyStore is ---> %s",kekKeyFromKeystore));

           /* // Now, delete KEK from the Keystore
            System.out.println("------------------------------------\n");
            System.out.println("Deleting KEK from the Keystore...");
            keyStore.deleteKek(EncryptionConstants.KEK_ENTRY_ALIAS);*/

            // Decrypt PRNG
            System.out.println("------------------------------------\n");
            System.out.println("Decrypting PRNG...");
            String decryptedPrng = EncryptionUtils.decrypt(masterKey, kekKeyFromKeystore, iv);
            System.out.println(String.format("Decrypted PRNG is ---> %s",decryptedPrng));

            // Generate DEK using PRNG
            System.out.println("------------------------------------\n");
            SecretKey dekKey = EncryptionUtils.generateSecretKey(decryptedPrng, salt);
            System.out.println(String.format("Generated DEK ---> %s",dekKey));

            // Decrypt password
            String decryptedPassword = EncryptionUtils.decrypt(password,dekKey, iv);
            System.out.println(String.format("Decrypted password  is ---> %s",decryptedPassword));

        } else {
            System.out.println("NOT A VALID MODE!!!");
        }


    }
}
