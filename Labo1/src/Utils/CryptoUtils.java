/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils;

import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

/**
 *
 * @author oussa
 */
public class CryptoUtils {
    public static final String ALGORITHM = "DESede/ECB/PKCS5Padding";
    public static final String KEYDES3 = "0123456789abcdef0123456789abcdef0123456789abcdef";
    

    public static byte[] encrypt(String message , String KEY, String ALGORITHM) throws Exception {
        KeySpec keySpec = new DESedeKeySpec(KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey key = keyFactory.generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }
    
     public static String decrypt(byte[] encryptedMessage, String KEY, String ALGORITHM) throws Exception {
        KeySpec keySpec = new DESedeKeySpec(KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey key = keyFactory.generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decryptedMessageBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }
}
