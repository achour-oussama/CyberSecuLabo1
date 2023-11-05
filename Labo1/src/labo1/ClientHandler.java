package labo1;

import Requete.Des3;
import Requete.Requete;
import static Requete.Requete.DES3;
import Utils.CryptoUtils;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    server mainFrame;

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    ClientHandler(ServerSocket serverS, server aThis) {
        this.serverSocket = serverS;
        mainFrame = aThis;
    }

    @Override
    public void run() {

        try {
            clientSocket = serverSocket.accept();
            in = new DataInputStream(clientSocket.getInputStream());
            out = new DataOutputStream(clientSocket.getOutputStream());
            obj = new ObjectInputStream(in);

            while (true) {
                Requete req = (Requete) obj.readObject();

                switch (req.getCode()) {
                    case Requete.DES3: {
                        Des3 des3 = (Des3) req.getRequete();

                        String message = CryptoUtils.decrypt(des3.getChargeutile(), CryptoUtils.KEYDES3, CryptoUtils.ALGORITHM);

                        mainFrame.updateWindows(message, new String(des3.getChargeutile(), StandardCharsets.UTF_8), CryptoUtils.KEYDES3);

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
