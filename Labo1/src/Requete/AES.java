/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Requete;

import java.io.Serializable;

/**
 *
 * @author oussa
 */
public class AES implements Serializable , IRequete{

    byte[] Message ;

    public AES(byte[] Message) {
        this.Message = Message;
    }

    public byte[] getMessage() {
        return Message;
    }

    public void setMessage(byte[] Message) {
        this.Message = Message;
    }
    
    
    @Override
    public byte[] getChargeutile() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
