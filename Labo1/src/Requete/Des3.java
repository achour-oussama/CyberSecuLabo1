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
public class Des3 implements IRequete, Serializable{
    
    private byte[] message;
   

    public Des3(byte[] mess) {
        message  = mess;
    }
  

  
    
    
    @Override
    public byte[] getChargeutile() {
        return message;
        
    }
    
}
