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
public class SHA1 implements Serializable , IRequete {

    String message;
    String Hash;

    public SHA1(String message, String Hash) {
        this.message = message;
        this.Hash = Hash;
    }

    public String getMessage() {
        return message;
    }

    public String getHash() {
        return Hash;
    }
    
    
    
    @Override
    public byte[] getChargeutile() {
         return null;
    }
    
}
