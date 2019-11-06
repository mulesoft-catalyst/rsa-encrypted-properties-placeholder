package com.mulesoft.ps.apac.encryption;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;

public class RsaUtility {
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }
    
    private static boolean isAbsolutePath(String file) {
        return new File(file).isAbsolute();
    }

    public static KeyPair getKeyPairFromKeyStore(String keyStorePath , String keyStorePass , String keyPass , String keyAlias) throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks
    	InputStream ins = isAbsolutePath(keyStorePath) ? new FileInputStream(keyStorePath) : RsaUtility.class.getResourceAsStream("/"+keyStorePath);

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, keyStorePass.toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection(keyPass.toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate(keyAlias);
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }


    public static void main(String... argv) throws Exception {
        
    	String output = null;
    	
    	String keyStorePath = "keystore/keystore.jks";
    	String keyStorePass = "s3cr3t";
    	String keyPass = "s3cr3t";
    	String keyAlias = "mykey";
    	
    	
    	String operation = argv[0];
    	String inputString = argv[1];
    	
    	if(argv.length > 2) {
    		 keyStorePath = argv[2];
        	 keyStorePass = argv[3];
        	 keyPass = argv[4];
        	 keyAlias = argv[5];
    	}
    			
    	
        KeyPair pair = getKeyPairFromKeyStore(keyStorePath , keyStorePass , keyPass , keyAlias);
        
        switch(operation) {
        	case "encrypt" :
        		output = encrypt(inputString, pair.getPublic());
        		break;
        	case "decrypt" :
        		output = decrypt(inputString, pair.getPrivate());
        		break;
        	default:
        		System.out.println("Operation not supported. Please enter encrypt or decrypted");
        }
        
        if(null!=output) {
        	System.out.println(output);
        }

        
    }
}