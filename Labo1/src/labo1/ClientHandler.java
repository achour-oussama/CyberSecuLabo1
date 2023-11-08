package labo1;

import Requete.AES;
import Requete.Des3;
import Requete.DiffieHellMans;
import Requete.HMAC;
import Requete.Requete;
import static Requete.Requete.AES;
import static Requete.Requete.DES3;
import static Requete.Requete.SHA1;
import static Requete.Requete.SHA1withRSA;
import static Requete.Requete.certif;
import Requete.SHA1;
import Requete.SHA1withRSA;
import Requete.certif;
import Utils.CryptoUtils;
import static Utils.CryptoUtils.*;
import Utils.RandomCoprimeNumbers;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.swing.JOptionPane;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author oussa
 */
public class ClientHandler implements Runnable {

    private Socket clientSocket;
    private ServerSocket serverSocket;
    DataInputStream in;
    DataOutputStream out;
    ObjectInputStream obj;
    ObjectOutputStream objO;
    server mainFrame;
    private int B;
    private SecretKey aesKey;

    String filePathLaptop = "C:\\Users\\oussa\\OneDrive\\Bureau\\CyberSecuLabo1\\key\\";
    String filePathComputer = "C:\\Users\\oussa\\Desktop\\CyberSecuLabo1\\key\\";

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    ClientHandler(ServerSocket serverS, server aThis) {
        this.serverSocket = serverS;
        mainFrame = aThis;
        B = new Random().nextInt();
    }

    @Override
    public void run() {
        boolean laptop = true;
        String filepath;
        if (laptop) {
            filepath = filePathLaptop;
        } else {
            filepath = filePathComputer;
        }

        try {
            clientSocket = serverSocket.accept();
            in = new DataInputStream(clientSocket.getInputStream());
            out = new DataOutputStream(clientSocket.getOutputStream());
            obj = new ObjectInputStream(in);
            objO = new ObjectOutputStream(out);

            while (true) {
                Requete req = (Requete) obj.readObject();

                switch (req.getCode()) {
                    case Requete.DES3: {
                        Des3 des3 = (Des3) req.getRequete();

                        String message = decrypt(des3.getChargeutile(), KEYDES3, ALGORITHM);

                        mainFrame.updateWindows(message, new String(des3.getChargeutile(), StandardCharsets.UTF_8), KEYDES3);

                        req = null;

                    }

                    case Requete.DIFFIE: {
                        DiffieHellMans dmf = (DiffieHellMans) req.getRequete();

                        if (verifySignatures(dmf.getSign(), getCertificateSignature(filepath + "server.jce", "oussama", "client"))) {
                            String message = decryptWithPublicKey(dmf.getChargeutile(), dmf.getFilePublicKey());

                            if (message.equals("client")) {
                                byte[] sign = getCertificateSignature(filepath + "server.jce", "oussama", "server");
                                PrivateKey prk = getPrivateKeyFromKeystore(filepath + "server.jce", "oussama", "server", "server".toCharArray());
                                PublicKey pkb = getPublicKeyFromKeystore(filepath + "server.jce", "oussama", "server", "server".toCharArray());
                                byte[] crypt = encryptWithPrivateKey("server".getBytes(), prk);

                                // Bob reçoit la clé publique d'Alice et la convertit en objet Key
                                KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
                                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(dmf.getAliceBobKey());
                                Key alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

                                KeyPair bobKeyPair = generateDHKeyPair();

                                // Bob fait un accord de clé avec Alice
                                KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
                                bobKeyAgree.init(bobKeyPair.getPrivate());
                                bobKeyAgree.doPhase(alicePubKey, true);

                                // Bob génère le secret partagé avec Alice
                                byte[] bobSharedSecret = bobKeyAgree.generateSecret();

                                // Bob dérive une clé AES à partir du secret partagé
                                aesKey = generateAESKey(bobSharedSecret);

                                DiffieHellMans dms = new DiffieHellMans(sign, crypt, pkb.getEncoded(), bobKeyPair.getPublic().getEncoded());
                                req = new Requete(Requete.AES, dms);

                                objO.writeObject(req);

                                req = null;

                            } else {
                                JOptionPane.showMessageDialog(null, "Mauvaise client ");
                            }

                        } else {
                            JOptionPane.showMessageDialog(null, "Mauvaise sign");
                        }

                    }
                    break;
                    case Requete.AES: {
                        AES aes = (AES) req.getRequete();

                        byte[] mess = aes.getChargeutile();

                        byte[] message = decryptWithAES(mess, aesKey);

                        mainFrame.updateWindows(new String(message, StandardCharsets.UTF_8), new String(mess, StandardCharsets.UTF_8), new String(aesKey.getEncoded(), StandardCharsets.UTF_8));
                        req = null;
                    }
                    break;
                    case Requete.SHA1: {
                        SHA1 sh = (SHA1) req.getRequete();
                        String newHash = hash(sh.getMessage());
                        if (sh.getHash().equals(newHash)) {
                            mainFrame.updateWindows(sh.getMessage(), sh.getHash(), "");
                        } else {
                            mainFrame.updateWindows("Hash Incorect", "Hash Incorect", "");
                        }
                    }
                    break;
                    case Requete.HMAC: {
                        HMAC hm = (HMAC) req.getRequete();

                        byte[] mac = hm.getMac();
                        byte[] mess = hm.getMess();

                        String decrypted = decrypt_message(mess, CryptoUtils.Hkey);

                        if (Arrays.equals(mac, hmac_md5(decrypted, CryptoUtils.Hkey))) {
                            mainFrame.updateWindows(decrypted, new String(mess, StandardCharsets.UTF_8), new String(mac, StandardCharsets.UTF_8));
                        } else {
                            mainFrame.updateWindows("Hash Incorect", "Hash Incorect", "");
                        }

                    }
                    break;
                    case Requete.SHA1withRSA: {
                        SHA1withRSA rsa = (SHA1withRSA) req.getRequete();

                        String message = decryptWithPublicKey(rsa.getCrypt(), rsa.getPublicKey());

                        if (verifySignature(message, rsa.getPublicKey(), rsa.getSign())) {
                            mainFrame.updateWindows(message, new String(rsa.getCrypt(), StandardCharsets.UTF_8), new String(rsa.getPublicKey(), StandardCharsets.UTF_8));
                        } else {
                            mainFrame.updateWindows("Hash Incorect", "Hash Incorect", "");
                        }

                    }
                    break;
                    case Requete.certif : {
                        certif cer  = (certif) req.getRequete();
                        
                        if (verifySignatures(cer.getSign(), getCertificateSignature(filepath + "server.jce", "oussama", "client")))
                        {
                            PublicKey pk = getPublicKeyFromKeystore(filepath + "server.jce", "oussama", "client", "client".toCharArray());
                            
                            String mess = decryptWithPublicKey(cer.getData(), pk.getEncoded());
                            mainFrame.updateWindows(mess, new String(cer.getData(), StandardCharsets.UTF_8), new String(pk.getEncoded(), StandardCharsets.UTF_8));
                            
                        }
                    }  
                     

                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ClientHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(ClientHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
