package org.experiments;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class AsymmetricEncryptionDemonstration {
    public static void main(String[] args) throws Exception {
        String textToEncrypt=args[0];
        Cipher cipher = Cipher.getInstance("RSA");
        Map<String, Object> keyDetails = generateKeys();
        byte[] encryptedText = encryptText(cipher, keyDetails.get("PublicKey"), textToEncrypt.getBytes());
        String decryptedText = decryptText(cipher, keyDetails.get("PrivateKey"), encryptedText);
        System.out.println("Plain text before encryption: "+textToEncrypt+", Encrypted text: "+new String(encryptedText)+" , Decrypted text: "+decryptedText);
    }

    private static byte[] encryptText (Cipher cipher, Object publicKey, byte[] plainBytes) throws Exception{
        PublicKey key = (PublicKey)publicKey;
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainBytes);
    }

    private static String decryptText (Cipher cipher,  Object privateKey, byte[] encryptedByText) throws Exception{
        PrivateKey key = (PrivateKey)privateKey ;
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes  = cipher.doFinal(encryptedByText);
        return new String(decryptedBytes);
    }

    private static Map<String,Object> generateKeys() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, Object> keys = new HashMap<String,Object>();
        keys.put("PrivateKey", privateKey);
        keys.put("PublicKey", publicKey);
        return keys;
    }
}
