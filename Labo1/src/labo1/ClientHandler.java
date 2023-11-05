package labo1;

import Requete.Des3;
import Requete.Requete;
import static Requete.Requete.DES3;
import Utils.CryptoUtils;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
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

    private final Socket clientSocket;
    DataInputStream in;
    DataOutputStream out;
    ObjectInputStream obj;
    mainWindows mainFrame;
    

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    ClientHandler(Socket clientSocket, mainWindows aThis) {
          this.clientSocket = clientSocket;
          mainFrame = aThis;
    }

    @Override
    public void run() {
        try {
            in = new DataInputStream(clientSocket.getInputStream());
            out = new DataOutputStream(clientSocket.getOutputStream());
            obj = new ObjectInputStream(in);
            
            Requete req  = (Requete) obj.readObject();
            
            switch(req.getCode())
            {
                case Requete.DES3 : {
                           Des3 des3 = (Des3) req.getRequete();
                           
                           String message  = CryptoUtils.decrypt(des3.getChargeutile(), Des3.KEY , Des3.ALGORITHM);
                           
                           mainFrame.updateWindows(message, new String(des3.getChargeutile(), StandardCharsets.UTF_8) , Des3.KEY);
                           
                           
                }
            }
            
            

            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ClientHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(ClientHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
