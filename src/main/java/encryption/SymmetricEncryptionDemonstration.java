package encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;

public class SymmetricEncryptionDemonstration {

    public static void main(String[] args) throws Exception {
        String textToEncrypt=args[0];
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Key keyDetails = generateKey();
        byte[] encryptedText = encryptText(cipher, keyDetails, textToEncrypt.getBytes());
        String decryptedText = decryptText(cipher, keyDetails, encryptedText);
        System.out.println("Plain text before encryption: "+textToEncrypt+", Encrypted text: "+new String(encryptedText)+" , Decrypted text: "+decryptedText);
    }

    private static byte[] encryptText (Cipher cipher, Key key, byte[] plainBytes) throws Exception{
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainBytes);
    }

    private static String decryptText (Cipher cipher, Key key, byte[] encryptedByText) throws Exception{
        cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
        byte[] decryptedBytes  = cipher.doFinal(encryptedByText);
        return new String(decryptedBytes);
    }

    private static Key generateKey() throws Exception{
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);  // Key size
        return keyGen.generateKey();
    }
}
