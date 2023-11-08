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
public class HandShake implements Serializable , IRequete {
    
    byte[] sign;
    byte[] publicKey;

    public HandShake(byte[] sign, byte[] publicKey) {
        this.sign = sign;
        this.publicKey = publicKey;
    }

    public byte[] getSign() {
        return sign;
    }

    public void setSign(byte[] sign) {
        this.sign = sign;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public byte[] getChargeutile() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    
    
}
