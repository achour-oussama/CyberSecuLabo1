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
public class HMAC implements Serializable , IRequete{

    byte[] mac;
    byte[] mess;

    public byte[] getMac() {
        return mac;
    }

    public void setMac(byte[] mac) {
        this.mac = mac;
    }

    public HMAC(byte[] mac, byte[] mess) {
        this.mac = mac;
        this.mess = mess;
    }

    public byte[] getMess() {
        return mess;
    }

    public void setMess(byte[] mess) {
        this.mess = mess;
    }
    
    
    
    @Override
    public byte[] getChargeutile() {
        return mac;
    }
    
}
