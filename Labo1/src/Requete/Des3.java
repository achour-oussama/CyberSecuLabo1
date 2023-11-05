/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Requete;

/**
 *
 * @author oussa
 */
public class Des3 implements IRequete{
    
    private byte[] message;
    public static final String ALGORITHM = "DESede/ECB/PKCS5Padding";
    public static final String KEY = "0123456789abcdef0123456789abcdef0123456789abcdef";

    public Des3(byte[] mess) {
        message  = mess;
    }
  

  
    
    
    @Override
    public byte[] getChargeutile() {
        return message;
        
    }
    
}
