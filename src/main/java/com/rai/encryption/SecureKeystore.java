package com.rai.encryption;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class SecureKeystore {
    private File configFolder;
    //private SecretKey secretKey;

    public SecureKeystore(File configFolder){
        this.configFolder = configFolder;
        //this.secretKey = secretKey;
    }




    public void storeKek(SecretKey secretKey, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        System.out.println(String.format("Storing KEK to KeyStore",secretKey));
        File keyStoreFolder = new File(configFolder, EncryptionConstants.KEYSTORE_SUBFOLDER);
        KeyStore ks = KeyStore.getInstance(EncryptionConstants.KEYSTORE_FOLDER);
        KeyStore.LoadStoreParameter param = new SecretFolderKeyStoreSpi.SecretFolderKeyStoreParameter(keyStoreFolder);
        ks.load(param);
        //ks.setKeyEntry(EncryptionConstants.KEK_ENTRY_ALIAS, secretKey, null, null);
        ks.setKeyEntry(alias, secretKey, null, null);
        ks.store(param);
    }

    public SecretKey retrieveKek() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        File keyStoreFolder = new File(configFolder, EncryptionConstants.KEYSTORE_SUBFOLDER);
        KeyStore ks = KeyStore.getInstance(EncryptionConstants.KEYSTORE_FOLDER);
        KeyStore.LoadStoreParameter param = new SecretFolderKeyStoreSpi.SecretFolderKeyStoreParameter(keyStoreFolder);
        ks.load(param);
        SecretKey kekKey = (SecretKey) ks.getKey(EncryptionConstants.KEK_ENTRY_ALIAS, null);
        if (!ks.containsAlias(EncryptionConstants.KEK_ENTRY_ALIAS)){
            throw new KeyStoreException(String.format("Retrieve KEK: Alias '%s' no longer exists in the KeyStore",EncryptionConstants.KEK_ENTRY_ALIAS));
        }
        System.out.println(String.format("Retrieve KEK: Ali as '%s' exists in the KeyStore",EncryptionConstants.KEK_ENTRY_ALIAS));
        return kekKey;
    }

    public void deleteKek(String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        File keyStoreFolder = new File(configFolder, EncryptionConstants.KEYSTORE_SUBFOLDER);
        KeyStore ks = KeyStore.getInstance(EncryptionConstants.KEYSTORE_FOLDER);
        KeyStore.LoadStoreParameter param = new SecretFolderKeyStoreSpi.SecretFolderKeyStoreParameter(keyStoreFolder);
        ks.load(param);
        if (ks.containsAlias(alias)){
            System.out.println(String.format("Delete KEK: Deleting KEK with alias %s from the KeyStore", alias));
            ks.deleteEntry(alias);
            // Flush
            ks.store(param);
        } else  {
            System.out.println(String.format("Delete KEK: Key with alias %s from the KeyStore not found!", alias));
        }
        /*ks.deleteEntry(EncryptionConstants.KEK_ENTRY_ALIAS);
        // Flush
        ks.store(param);
*/
    }


    public void storeIv(IvParameterSpec iv) throws IOException {

        System.out.println(String.format("Save IV file is - %s", configFolder+"/iv.ser"));

    	/*
    	IvWrapper ivWrapper = new IvWrapper();
        ivWrapper.setIv(iv);
        */

        try (FileOutputStream fos = new FileOutputStream("D:/Architecture/KeyStore/MyKeyStore/iv.ser");
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(iv);
            oos.flush();
        }

    }

    public IvParameterSpec retrieveIv() throws IOException, ClassNotFoundException {

        System.out.println(String.format("Retrieve IV file is - %s", configFolder+"/iv.ser"));

        Object result = null;
        try (FileInputStream fis = new FileInputStream("D:/Architecture/KeyStore/MyKeyStore/iv.ser");
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            result = ois.readObject();
        }

        if(result instanceof IvParameterSpec) {
            System.out.println("Instance of EqIvParameterSpec" + IvParameterSpec.class);
        }

        //IvWrapper iv = (IvWrapper)result;
        //System.out.println(String.format("Retrieve IV file is - %b", iv));
        return (IvParameterSpec)result;

    }
}
