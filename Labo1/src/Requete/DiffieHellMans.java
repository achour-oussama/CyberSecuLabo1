/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Requete;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;
import javax.crypto.KeyAgreement;

/**
 *
 * @author oussa
 */
public class DiffieHellMans implements Serializable , IRequete{
    BigInteger[] nq ;
    
    byte[] sign;
    byte[] crypt;
    byte[] pkb;
    byte[] dh;
    BigInteger alphaBeta ;
    byte[] agrement;

    public DiffieHellMans(byte[] sign, byte[] crypt, byte[] encoded, byte[] dhf, byte[] agrement ) {
       
        this.sign = sign;
        this.crypt = crypt;
          this.pkb = encoded;
             this.agrement = agrement;
           this.dh = dhf;
     
       
    
     
      
    }

    public  byte[] getAgrement() {
        return agrement;
    }

    public void setAgrement( byte[] agrement) {
        this.agrement = agrement;
    }
    
    
    public byte[] getSign() {
        return sign;
    }

    public byte[] getPkb() {
        return pkb;
    }
    
    

    public DiffieHellMans(byte[] sign, byte[] crypt, byte[] pkb, BigInteger[] number ,BigInteger alphaBeta) {
        this.sign = sign;
        this.crypt = crypt;
        this.pkb = pkb;
        this.nq = number;
        this.alphaBeta = alphaBeta;
    }
    
     public DiffieHellMans(byte[] sign, byte[] crypt, byte[] pkb ,BigInteger alphaBeta) {
        this.sign = sign;
        this.crypt = crypt;
        this.pkb = pkb;
        this.alphaBeta = alphaBeta;
    }

    public DiffieHellMans(BigInteger[] nq, byte[] pkb, BigInteger alphaBeta) {
        this.nq = nq;
        this.pkb = pkb;
        this.alphaBeta = alphaBeta;
    }
    
    

    public BigInteger[] getNq() {
        return nq;
    }

    public void setNq(BigInteger[] nq) {
        this.nq = nq;
    }

    public DiffieHellMans(BigInteger[] nq, BigInteger alphaBeta) {
        this.nq = nq;
        this.alphaBeta = alphaBeta;
    }

   

    public BigInteger getAlphaBeta() {
        return alphaBeta;
    }

    public void setAlphaBeta(BigInteger alphaBeta) {
        this.alphaBeta = alphaBeta;
    }
    
    


    @Override
    public byte[] getChargeutile() {
        return crypt;
    }
    
    
    
    
    
}
