/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package labo1;

import Requete.AES;
import Requete.Des3;
import Requete.DiffieHellMans;
import Requete.HMAC;
import Requete.HandShake;
import Requete.Requete;
import Requete.SHA1;
import Requete.SHA1withRSA;
import Requete.certif;
import Utils.CryptoUtils;
import Utils.RandomCoprimeNumbers;
import static Utils.RandomCoprimeNumbers.generateCoprimeNumbers;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.PrivateKey;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import static Utils.CryptoUtils.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.swing.JOptionPane;

/**
 *
 * @author oussa
 */
public class Client extends javax.swing.JFrame {

    /**
     * Creates new form Client
     */
    Socket socket;
    DataOutputStream out;
    DataInputStream in;
    ObjectOutputStream obj;
    ObjectInputStream objIn;
    int A;

    String filePathLaptop = "C:\\Users\\oussa\\OneDrive\\Bureau\\CyberSecuLabo1\\key\\";
    String filePathComputer = "C:\\Users\\oussa\\Desktop\\CyberSecuLabo1\\key\\";

    SecretKey aesKey = null;

    PublicKey ServerPublicKey = null;

    public Client() throws IOException {
        initComponents();
        socket = new Socket("localhost", 8080);
        out = new DataOutputStream(socket.getOutputStream());
        in = new DataInputStream(socket.getInputStream());
        obj = new ObjectOutputStream(out);
        objIn = new ObjectInputStream(in);
        A = new Random().nextInt();

    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        AES = new javax.swing.JRadioButton();
        DES3 = new javax.swing.JRadioButton();
        jLabel2 = new javax.swing.JLabel();
        SHA1 = new javax.swing.JRadioButton();
        HMAC = new javax.swing.JRadioButton();
        jButton1 = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        SHA1withRSA = new javax.swing.JRadioButton();
        Certificat = new javax.swing.JRadioButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        buttonGroup1.add(AES);
        AES.setText("AES");
        AES.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AESActionPerformed(evt);
            }
        });

        buttonGroup1.add(DES3);
        DES3.setText("DES3");

        jLabel2.setText("Choix du cryptage : ");

        buttonGroup1.add(SHA1);
        SHA1.setText("SHA-1");

        buttonGroup1.add(HMAC);
        HMAC.setText("HMAC-MD5");

        jButton1.setText("Envoie");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jLabel1.setText("Texte  : ");

        jTextField1.setText("Je mange la glace ");

        buttonGroup1.add(SHA1withRSA);
        SHA1withRSA.setText("SHA1withRSA");
        SHA1withRSA.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SHA1withRSAActionPerformed(evt);
            }
        });

        buttonGroup1.add(Certificat);
        Certificat.setText("certificat");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(57, 57, 57)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2)
                            .addComponent(DES3)
                            .addComponent(AES)
                            .addComponent(SHA1)
                            .addComponent(HMAC))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 268, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(18, 18, 18)
                                        .addComponent(jLabel1)))
                                .addContainerGap())
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 132, Short.MAX_VALUE)
                                .addComponent(jButton1)
                                .addGap(235, 235, 235))))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(Certificat)
                            .addComponent(SHA1withRSA))
                        .addGap(0, 0, Short.MAX_VALUE))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(93, 93, 93)
                        .addComponent(jLabel2)
                        .addGap(25, 25, 25))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel1)))
                .addGap(3, 3, 3)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(44, 44, 44)
                        .addComponent(jButton1))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(DES3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(AES)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(SHA1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(HMAC)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(SHA1withRSA)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(Certificat)
                .addContainerGap(86, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed

        boolean laptop = true;
        String filepath;
        if (laptop) {
            filepath = filePathLaptop;
        } else {
            filepath = filePathComputer;
        }
        try {

            String texte = jTextField1.getText();

            if (DES3.isSelected()) {
                byte[] encrypted = CryptoUtils.encrypt(texte, CryptoUtils.KEYDES3, CryptoUtils.ALGORITHM);
                Des3 des = new Des3(encrypted);
                Requete req = new Requete(Requete.DES3, des);

                obj.writeObject(req);

            } else {
                if (AES.isSelected()) {
                    if (aesKey == null) {

                        KeyPair aliceKeyPair = generateDHKeyPair();
                        byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();
                        String client = "client";

                        PublicKey pk = getPublicKeyFromKeystore(filepath + "client.jce", "oussama", "client", "client".toCharArray());
                        PrivateKey prk = getPrivateKeyFromKeystore(filepath + "client.jce", "oussama", "client", "client".toCharArray());

                        byte[] crypt = encryptWithPrivateKey(client.getBytes(), prk);
                        byte[] sign = getCertificateSignature(filepath + "client.jce", "oussama", "client");

                        DiffieHellMans dms = new DiffieHellMans(sign, crypt, pk.getEncoded(), alicePubKeyEnc);

                        Requete req = new Requete(Requete.DIFFIE, dms);

                        obj.writeObject(req);

                        req = (Requete) objIn.readObject();

                        dms = (DiffieHellMans) req.getRequete();

                        sign = dms.getSign();

                        if (verifySignatures(sign, getCertificateSignature(filepath + "client.jce", "oussama", "server"))) {

                            byte[] byteServerKey = dms.getPkb();

                            String message = decryptWithPublicKey(dms.getChargeutile(), byteServerKey);

                            if (message.equals("server")) {

                                KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
                                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(dms.getAliceBobKey());
                                Key bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);

                                // Alice fait un accord de clé avec Bob
                                KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
                                aliceKeyAgree.init(aliceKeyPair.getPrivate());
                                aliceKeyAgree.doPhase(bobPubKey, true);

                                // Alice génère le secret partagé avec Bob
                                byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();

                                // Alice dérive une clé AES à partir du secret partagé
                                aesKey = generateAESKey(aliceSharedSecret);

                                AES aes = new AES(encryptWithAES(jTextField1.getText(), aesKey));

                                req = new Requete(Requete.AES, aes);

                                obj.writeObject(req);

                            } else {
                                JOptionPane.showMessageDialog(null, "Receveur incorect ");
                            }

                        } else {
                            JOptionPane.showMessageDialog(null, "Signature incorect ");
                        }

                    }
                } else {
                    if (SHA1.isSelected()) {
                        texte = jTextField1.getText();

                        SHA1 sh = new SHA1(texte, hash(texte));

                        Requete req = new Requete(Requete.SHA1, sh);

                        obj.writeObject(req);

                    } else {
                        if (HMAC.isSelected()) {
                            texte = jTextField1.getText();

                            HMAC hm = new HMAC(hmac_md5(texte, CryptoUtils.Hkey), crypt_messageHmac(texte, CryptoUtils.Hkey));

                            Requete req = new Requete(Requete.HMAC, hm);

                            obj.writeObject(req);
                        } else {
                            if (SHA1withRSA.isSelected()) {
                                if (ServerPublicKey == null) {
                                    PublicKey pk = getPublicKeyFromKeystore(filepath + "client.jce", "oussama", "client", "client".toCharArray());
                                    PrivateKey prk = getPrivateKeyFromKeystore(filepath + "client.jce", "oussama", "client", "client".toCharArray());

                                    byte[] sign = sign_message( jTextField1.getText(), prk);
                                    byte[] crypt = encryptWithPrivateKey(jTextField1.getText().getBytes(), prk);
                                    byte[] publicKey = pk.getEncoded();
                                    
                                    SHA1withRSA sha = new SHA1withRSA(publicKey , sign , crypt);
                                    
                                    Requete req  = new Requete(Requete.SHA1withRSA, sha);
                                    
                                    obj.writeObject(obj);
                                  
                                }

                            } else if(Certificat.isSelected())
                            {
                                  PublicKey pk = getPublicKeyFromKeystore(filepath + "client.jce", "oussama", "client", "client".toCharArray());
                                  PrivateKey prk = getPrivateKeyFromKeystore(filepath + "client.jce", "oussama", "client", "client".toCharArray());
                                  byte[] sign = getCertificateSignature(filepath + "client.jce", "oussama", "client");
                                  
                                  certif cer  = new certif(sign , encryptWithPrivateKey(jTextField1.getText().getBytes(), prk));
                                  
                                  Requete req = new Requete(Requete.certif, cer);
                                  System.out.println("certif");
                                  obj.writeObject(req);
                            }
                        }
                    }
                }
            }

        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_jButton1ActionPerformed

    private void AESActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AESActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_AESActionPerformed

    private void SHA1withRSAActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SHA1withRSAActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_SHA1withRSAActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Client.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Client.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Client.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Client.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    new Client().setVisible(true);
                } catch (IOException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JRadioButton AES;
    private javax.swing.JRadioButton Certificat;
    private javax.swing.JRadioButton DES3;
    private javax.swing.JRadioButton HMAC;
    private javax.swing.JRadioButton SHA1;
    private javax.swing.JRadioButton SHA1withRSA;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JTextField jTextField1;
    // End of variables declaration//GEN-END:variables
}
