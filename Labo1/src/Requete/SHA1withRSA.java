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
public class SHA1withRSA  implements Serializable , IRequete{
    byte[] publicKey;
    byte[] sign;
    byte[] crypt;

    public SHA1withRSA(byte[] publicKey, byte[] sign, byte[] crypt) {
        this.publicKey = publicKey;
        this.sign = sign;
        this.crypt = crypt;
    }

    
    
    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getSign() {
        return sign;
    }

    public void setSign(byte[] sign) {
        this.sign = sign;
    }

    public byte[] getCrypt() {
        return crypt;
    }

    public void setCrypt(byte[] crypt) {
        this.crypt = crypt;
    }
    
    
    

    @Override
    public byte[] getChargeutile() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
