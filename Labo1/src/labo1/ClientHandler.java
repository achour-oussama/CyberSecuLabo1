package labo1;

import Requete.AES;
import Requete.Des3;
import Requete.DiffieHellMans;
import Requete.Requete;
import static Requete.Requete.AES;
import static Requete.Requete.DES3;
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
        if(laptop)
            filepath = filePathLaptop;
        else filepath = filePathComputer;
        
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

                        if (verifySignatures(dmf.getSign(), getCertificateSignature( filepath + "server.jce", "oussama", "client"))) {
                            String message = decryptWithPublicKey(dmf.getChargeutile(), dmf.getFilePublicKey());

                            if (message.equals("client")) {
                                byte[] sign = getCertificateSignature( filepath + "server.jce", "oussama", "server");
                                PrivateKey prk = getPrivateKeyFromKeystore( filepath + "server.jce", "oussama", "server", "server".toCharArray());
                                PublicKey pkb = getPublicKeyFromKeystore( filepath + "server.jce", "oussama", "server", "server".toCharArray());
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
                                aesKey =  generateAESKey(bobSharedSecret);
                                
                                


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
