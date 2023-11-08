/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author oussa
 */
public class CryptoUtils {

    public static final String ALGORITHM = "DESede/ECB/PKCS5Padding";
    public static final String KEYDES3 = "0123456789abcdef0123456789abcdef0123456789abcdef";
    public static final String Hkey = "123456789012345678901234";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] encrypt(String message, String KEY, String ALGORITHM) throws Exception {
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

    public static int GenerateKey(int alphaBeta1, int[] nq, float AB) {
        return (int) Math.pow(alphaBeta1, AB) % nq[0];
    }

    public static boolean verifySignature(byte[] signatureBytes, byte[] publicKeyBytes, byte[] dataToVerify) {
        try {

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);

            signature.update(dataToVerify);

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] decryptWithAES(byte[] encryptedData, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] decryptedData = cipher.doFinal(encryptedData);
            return decryptedData;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] encryptWithAES(String data, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            return encryptedBytes;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static PublicKey getPublicKeyFromKeystore(String keystorePath, String keystorePassword, String alias, char[] keyPassword) {
        try {
            FileInputStream fileInputStream = new FileInputStream(keystorePath);

            KeyStore keystore = KeyStore.getInstance("JCEKS");
            keystore.load(fileInputStream, keystorePassword.toCharArray());

            // Récupérer la clé publique à partir du keystore en utilisant l'alias
            PublicKey publicKey = keystore.getCertificate(alias).getPublicKey();

            return publicKey;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static PrivateKey getPrivateKeyFromKeystore(String keystorePath, String keystorePassword, String alias, char[] keyPassword) {
        try {
            FileInputStream fileInputStream = new FileInputStream(keystorePath);

            KeyStore keystore = KeyStore.getInstance("JCEKS");
            keystore.load(fileInputStream, keystorePassword.toCharArray());

            PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, keyPassword);

            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] createDigitalSignature(byte[] data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean verifyDigitalSignature(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature verifySignature = Signature.getInstance("SHA256withRSA");
            verifySignature.initVerify(publicKey);
            verifySignature.update(data);
            return verifySignature.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] encryptWithPrivateKey(byte[] data, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] getCertificateSignature(String keystorePath, String keystorePassword, String alias) {
        try {
            FileInputStream fileInputStream = new FileInputStream(keystorePath);

            KeyStore keystore = KeyStore.getInstance("JCEKS");
            keystore.load(fileInputStream, keystorePassword.toCharArray());

            Certificate cert = keystore.getCertificate(alias);

            if (cert instanceof X509Certificate) {
                X509Certificate x509Cert = (X509Certificate) cert;
                return x509Cert.getSignature();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verifySignatures(byte[] signature1, byte[] signature2) {
        if (signature1.length != signature2.length) {
            return false; // Si les longueurs des signatures sont différentes, elles sont différentes
        }

        for (int i = 0; i < signature1.length; i++) {
            if (signature1[i] != signature2[i]) {
                return false; // Si les valeurs des bytes diffèrent, les signatures sont différentes
            }
        }

        return true; // Les deux signatures sont identiques
    }

    public static String decryptWithPublicKey(byte[] encryptedData, byte[] publicKeyBytes) {
        try {
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);

            byte[] decryptedBytes = cipher.doFinal(encryptedData);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static KeyAgreement generateKeyAgreement(PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException {

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(key);
        return keyAgreement;
    }

    public static SecretKey deriveSharedSecret(KeyAgreement keyAgreement, PublicKey otherPublicKey) throws InvalidKeyException, NoSuchAlgorithmException {
        keyAgreement.doPhase(otherPublicKey, true);

        // Génération de la clé secrète partagée
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Création d'un objet SecretKey avec la clé secrète
        return new SecretKeySpec(sharedSecret, "AES");
    }

    // Générer une paire de clés Diffie-Hellman
    public static KeyPair generateDHKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(2048); // taille du modulo p
        return kpg.generateKeyPair();
    }

    // Générer une clé AES à partir d'un secret partagé Diffie-Hellman
    public static SecretKey generateAESKey(byte[] sharedSecret) throws Exception {
        // Utiliser SHA-256 pour dériver une clé de 128 bits à partir du secret partagé
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = new byte[16];
        sha256.update(sharedSecret, 0, sharedSecret.length);
        System.arraycopy(sha256.digest(), 0, keyBytes, 0, keyBytes.length);
        // Créer une clé AES à partir des octets dérivés
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        return key;
    }

    // Chiffrer un message avec une clé AES
    public static byte[] encryptAES(Key key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // Déchiffrer un message avec une clé AES
    public static byte[] decryptAES(Key key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // Convertir un tableau d'octets en une chaîne hexadécimale
    public static String toHex(byte[] data) {
        BigInteger bi = new BigInteger(1, data);
        return String.format("%0" + (data.length << 1) + "X", bi);
    }

    // Convertir une chaîne hexadécimale en un tableau d'octets
    public static byte[] fromHex(String hex) {
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return data;
    }

    public static String hash(String message) throws Exception {
        // Créer une instance de MessageDigest avec l'algorithme SHA-1
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        // Mettre à jour le digest avec les octets du message
        md.update(message.getBytes());
        // Calculer le hachage et le convertir en un tableau d'octets
        byte[] hash = md.digest();
        // Convertir le tableau d'octets en une chaîne hexadécimale
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        // Retourner la chaîne hexadécimale
        return sb.toString();
    }

    public static byte[] hmac_md5(String message, String key) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacMD5");
        mac.init(secretKeySpec);
        return mac.doFinal(message.getBytes());
    }

    public static byte[] crypt_messageHmac(String message, String key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "TripleDES");
        Cipher cipher = Cipher.getInstance("TripleDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

    }

    public static String decrypt_message(byte[] message, String key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "TripleDES");
        Cipher cipher = Cipher.getInstance("TripleDES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decrypted = cipher.doFinal(message);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static byte[] sign_message(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        return signature.sign();

    }

    public static boolean verifySignature(String message, byte[] signatureBytes, byte[] publicKeyBytes) throws Exception {
        // Créer une instance de X509EncodedKeySpec à partir du tableau de bytes de la clé publique
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

        // Créer une instance de KeyFactory pour l'algorithme de chiffrement que vous utilisez
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // ou "EC" ou autre

        // Générer une instance de PublicKey à partir de la clé publique
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Créer une instance de Signature pour l'algorithme de chiffrement que vous utilisez
        Signature signature = Signature.getInstance("SHA256withRSA"); // ou "SHA1withECDSA" ou autre

        // Initialiser la signature avec la clé publique
        signature.initVerify(publicKey);

        // Mettre à jour la signature avec le message
        signature.update(message.getBytes());

        // Vérifier la signature avec la signature fournie
        return signature.verify(signatureBytes);
    }

    public  PublicKey getPublicKeyFromCertificate(String keystorePath, String keystorePassword, String alias) throws Exception {
        // Créer une instance de FileInputStream à partir du chemin de fichier de keystore
        FileInputStream fileInputStream = new FileInputStream(keystorePath);

        // Créer une instance de KeyStore pour le type de keystore que vous utilisez
        KeyStore keystore = KeyStore.getInstance("JCEKS"); // ou "JKS" ou autre

        // Charger le keystore à partir du FileInputStream et du mot de passe
        keystore.load(fileInputStream, keystorePassword.toCharArray());

        // Récupérer le certificat à partir de l'alias fourni
        Certificate cert = keystore.getCertificate(alias);

        // Vérifier que le certificat est de type X509Certificate
        if (cert instanceof X509Certificate) {
            // Récupérer la clé publique du certificat et la renvoyer sous forme de tableau de bytes
            X509Certificate x509Cert = (X509Certificate) cert;
            return x509Cert.getPublicKey();
        }

        // Si le certificat n'est pas de type X509Certificate, renvoyer null
        return null;
    }

}
