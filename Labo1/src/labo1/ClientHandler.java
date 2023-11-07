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
import java.security.PrivateKey;
import java.security.PublicKey;
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

                    }

                    case Requete.DIFFIE: {
                        DiffieHellMans dmf = (DiffieHellMans) req.getRequete();

                        if (verifySignatures(dmf.getSign(), getCertificateSignature("C:\\Users\\oussa\\Desktop\\CyberSecuLabo1\\key\\server.jce", "oussama", "client"))) {
                            String message = decryptWithPublicKey(dmf.getChargeutile(), dmf.getPkb());

                            if (message.equals("client")) {
                                byte[] sign = getCertificateSignature("C:\\Users\\oussa\\Desktop\\CyberSecuLabo1\\key\\server.jce", "oussama", "server");
                                PrivateKey prk = getPrivateKeyFromKeystore("C:\\Users\\oussa\\Desktop\\CyberSecuLabo1\\key\\server.jce", "oussama", "server", "server".toCharArray());
                                PublicKey pkb = getPublicKeyFromKeystore("C:\\Users\\oussa\\Desktop\\CyberSecuLabo1\\key\\server.jce", "oussama", "server", "server".toCharArray());
                                byte[] crypt = encryptWithPrivateKey("server".getBytes(), prk);

                                byte[] keyAByte = dmf.getAgrement();
                                KeyAgreement KeyA  = 
                                KeyAgreement keyB = generateKeyAgreement();
                                

                                aesKey = deriveSharedSecret(keyA, pkb);

                                DiffieHellMans dms = new DiffieHellMans(sign, crypt, pkb.getEncoded(), keyB);
                                req = new Requete(Requete.AES, dms);

                                objO.writeObject(req);

                            } else {
                                JOptionPane.showMessageDialog(null, "Mauvaise client ");
                            }

                        } else {
                            JOptionPane.showMessageDialog(null, "Mauvaise sign");
                        }

                    }

                    case Requete.AES: {
                        AES aes = (AES) req.getRequete();

                        byte[] mess = aes.getChargeutile();

                        byte[] message = decryptWithAES(mess, aesKey);

                        mainFrame.updateWindows(new String(message, StandardCharsets.UTF_8), new String(mess, StandardCharsets.UTF_8), new String(aesKey.getEncoded(), StandardCharsets.UTF_8));
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
