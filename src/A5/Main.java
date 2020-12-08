package A5;

import javax.crypto.SecretKey;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Exercici 1
        KeyPair keys = activitat5.randomGenerate(1024);
        System.out.println("Privada: "+keys.getPrivate());
        System.out.println("Pública: "+keys.getPublic());

        System.out.println("Introdueix el missatge a xifrar: ");
        String msg = scanner.nextLine();
        byte[] msgBytes = msg.getBytes();
        byte[] mensXifrat = activitat5.encryptData(msgBytes, keys.getPublic());
        System.out.println("Missatge Xifrat");

        byte[] mensDex = activitat5.decryptData(mensXifrat, keys.getPrivate());
        System.out.println("Missatge Desxifrat");
        String missatgeDesxifrat = new String(mensDex);
        System.out.println("Missatge: "+missatgeDesxifrat);


        System.out.println("----------------------------------------------------------------------------------");

        KeyStore keystore = null;

        // Exercici 2
        try {
            keystore = activitat5.loadKeyStore("/home/dam2a/Escriptori/provadekeystore.keystore","jabali");
            System.out.println("Tipus de la KeyStore: "+ keystore.getType());
            System.out.println("Mida: "+ keystore.size());
            System.out.println("Alies de les claus: "+keystore.aliases().nextElement());
            System.out.println("Certificat d'una clau: "+keystore.getCertificate("mykey"));
            System.out.println(keystore.getCertificate("mykey").getPublicKey().getAlgorithm());

        } catch (Exception e) {
            e.printStackTrace();
        }

        String contra = "contrasenya";
        SecretKey secretkey = activitat5.passwordKeyGeneration(contra,128);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretkey);
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection("password".toCharArray());

        try {
            keystore.setEntry("mynewkey",secretKeyEntry,protectionParameter);
            FileOutputStream fos = new FileOutputStream("/home/dam2a/Escriptori/provadekeystore.keystore");
            keystore.store(fos, "jabali".toCharArray());
        } catch (KeyStoreException | FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("----------");
        System.out.println("Exercici 3");
        System.out.println("----------");

        System.out.println("----------");
        System.out.println("Exercici 4");
        System.out.println("----------");


        System.out.println("----------");
        System.out.println("Exercici 5");
        System.out.println("----------");
        System.out.println("Introdueix un missatge");
        String ex = scanner.nextLine();

        byte [] pop = ex.getBytes();
        byte [] signature = activitat5.signData(pop, keys.getPrivate());

        String sign = new String(signature);
        System.out.println(sign);


        System.out.println("----------");
        System.out.println("Exercici 6");
        System.out.println("----------");

        boolean ValidSign = activitat5.validateSignature(pop,signature, keys.getPublic());
        System.out.println("És valid?: "+ValidSign);
    }
}