/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Requete;

import java.awt.RenderingHints.Key;
import java.io.Serializable;

/**
 *
 * @author oussa
 */
public class Requete implements Serializable{
    
     public static final int DES3 = 1;
    
     private int code;
     IRequete requete;

    public Requete(int code, IRequete requete) {
        this.code = code;
        this.requete = requete;
    }

    public int getCode() {
        return code;
    }

    public IRequete getRequete() {
        return requete;
    }
     
     
}
