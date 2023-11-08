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
public class certif implements Serializable ,IRequete {
    byte[] sign;
    byte[] data;

    public byte[] getSign() {
        return sign;
    }

    public void setSign(byte[] sign) {
        this.sign = sign;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public certif(byte[] sign, byte[] data) {
        this.sign = sign;
        this.data = data;
    }

    @Override
    public byte[] getChargeutile() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
