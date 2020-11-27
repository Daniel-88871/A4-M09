package com.company;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class exercici1i2 {
    public static void main(String[] args) throws IOException {
        System.out.println("Xifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1");
        System.out.println("Prova alguns dels mètodes que proporciona la classe SecretKey");

        String missatge = "Bon día!";
        SecretKey secretkey = exercici1.keygenKeyGeneration(256);


        byte[] missatgeXifrat = exercici1.encryptData(secretkey, missatge.getBytes());
        byte[] missatgeDesxifrat = exercici1.decryptData(secretkey, missatgeXifrat);


        String Desxifrat = new String(missatgeDesxifrat);
        System.out.println(Desxifrat);
        System.out.println(Arrays.toString(secretkey.getEncoded()));
        System.out.println(secretkey.getFormat());


        System.out.println("---------------------------------------------------------------------------------------------------");
        System.out.println("Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas");
        System.out.println("---------------------------------------------------------------------------------------------------");

        String missatge2 = "Bones tardes!";
        String passwd = "bicicleta";
        SecretKey secretkey2 = exercici1.passwordKeyGeneration(passwd, 256);


        byte[] missatgeXifrat2 = exercici1.encryptData(secretkey2, missatge2.getBytes());
        byte[] missatgeDesxifrat2 = exercici1.decryptData(secretkey2, missatgeXifrat2);


        String Desxifrat2 = new String(missatgeDesxifrat2);
        System.out.println(Desxifrat2);


        System.out.println("--------------------------------------------------------------------------------------------------------------------");
        System.out.println("Desxifra el text del punt 6 i comprova que donant una paraula de pas incorrecte salta l'excepció BadPaddingException");
        System.out.println("--------------------------------------------------------------------------------------------------------------------");

        String passwd2 = "ciclomotor";
        SecretKey sk3 = exercici1.passwordKeyGeneration(passwd2, 256);


        try {
            byte[] missatgeDesxifrat3 = exercici1.decryptData(sk3, missatgeXifrat2);

            String Desxifrat3 = new String(missatgeDesxifrat3);
            System.out.println(Desxifrat3);



        } catch (Exception k) {
            System.out.println(k);
        }


        System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        System.out.println("Donat un text xifrat (textamagat) amb algoritme estàndard AES i clau simètrica generada amb el mètode SHA-256 a partir d’una contrasenya, i donat un fitxer (clausA4.txt) on hi ha possibles contrasenyes correctes, fes un programa per trobar la bona i desxifrar el missatge.");
        System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        String home = System.getProperty("user.home");
        File file = new File(home + "/" + "clausA4.txt");
        FileReader Fr = new FileReader(file);
        BufferedReader Br = new BufferedReader(Fr);
        String linia = Br.readLine();
        Path path = Paths.get(home + "/" + "textamagat");


        byte[] textEnBytes = Files.readAllBytes(path);
        boolean z = false;
        while (!z) {

            try {
                SecretKey password = exercici1.passwordKeyGeneration(linia, 128);

                byte[] textDesamagat = exercici1.decryptData(password, textEnBytes);

                String MissatgeDesamagat = new String(textDesamagat);
                System.out.println(MissatgeDesamagat);
                System.out.println("La contrasenya correcta es: " + linia);
                z = true;
                break;

            } catch (Exception k) {
                System.out.println("La contrasenya incorrecta es: " + linia + " ");
                linia = Br.readLine();
            }
        }
    }
}