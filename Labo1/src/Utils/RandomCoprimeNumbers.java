/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils;

import java.math.BigInteger;
import java.util.Random;

/**
 *
 * @author oussa
 */
public class RandomCoprimeNumbers {
    public static void main(String[] args) {
        int[] coprimeNumbers = generateCoprimeNumbers();
        System.out.println("Deux nombres premiers entre eux : " + coprimeNumbers[0] + " et " + coprimeNumbers[1]);
    }

    // Méthode pour vérifier si deux floats sont "premiers" entre eux (pour des floats)
    public static boolean areCoprime(float a, float b) {
        return Math.abs(a - b) > 1.0f; // Un exemple simple pour simuler la coprimarité entre floats
    }

    // Méthode pour générer deux floats aléatoires "premiers" entre eux
   public static int[] generateCoprimeNumbers() {
        Random random = new Random();
        int[] coprimePair = new int[2];

        do {
            coprimePair[0] = random.nextInt(100) + 1; // Génère un entier aléatoire entre 1 et 100
            coprimePair[1] = random.nextInt(100) + 1; // Génère un autre entier aléatoire entre 1 et 100
        } while (!areCoprime(coprimePair[0], coprimePair[1]));

        return coprimePair;
    }
    
      public static int generateAlphaBeta(int[] pq , int ab) {
         return (int) Math.pow(ab, pq[0]) % pq[1];
      
    }
}
