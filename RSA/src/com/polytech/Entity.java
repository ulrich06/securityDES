package com.polytech;

import java.lang.reflect.Array;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import javax.crypto.Cipher;

public class Entity {

	// keypair
	public PublicKey thePublicKey;
	private PrivateKey thePrivateKey;
	
	/**
	  * Entity Constructor
	  * Public / Private Key generation
	 **/
	public Entity(){
		// INITIALIZATION

		// generate a public/private key
		try{
			// get an instance of KeyPairGenerator  for RSA
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			// Initialize the key pair generator for 1024 length
			kpg.initialize(1024);
			// Generate the key pair
			KeyPair kp = kpg.genKeyPair();
			
			// save the public/private key
			thePublicKey = kp.getPublic();
			thePrivateKey = kp.getPrivate();
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
		}
	}

	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] sign(byte[] aMessage){
		
		try{
			// use of java.security.Signature
			// Init the signature with the private key
			Signature sign = Signature.getInstance("MD5withRSA");
			
			sign.initSign(thePrivateKey);
			// update the message
			sign.update(aMessage);
			// sign
			return sign.sign();
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean checkSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// use of java.security.Signature
			// init the signature verification with the public key
			Signature sign = Signature.getInstance("MD5withRSA");
			sign.initVerify(aPK);
			// update the message
			sign.update(aMessage);
			// check the signature
			
			return sign.verify(aSignature);
		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}
	
	
	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] mySign(byte[] aMessage){
		
		try{
			// get an instance of a cipher with RSA with ENCRYPT_MODE
			Cipher cipher = Cipher.getInstance("RSA");
			// Init the signature with the private key
			cipher.init(Cipher.ENCRYPT_MODE, this.thePrivateKey);
			// get an instance of the java.security.MessageDigest with MD5
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			// process the digest
			byte[] digest = md5.digest(aMessage);
			// return the encrypted digest
	
			return cipher.doFinal(digest);
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean myCheckSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// get an instance of a cipher with RSA with ENCRYPT_MODE
			Cipher cipher = Cipher.getInstance("RSA");
			// Init the signature with the public key
			cipher.init(Cipher.DECRYPT_MODE, aPK);
			// decrypt the signature
			byte[] signDecrypt = cipher.doFinal(aSignature);
			// get an instance of the java.security.MessageDigest with MD5
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			// process the digest
			byte[] digest = md5.digest(aMessage);
			
			return Arrays.equals(digest, signDecrypt);

		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}	
	
	
	/**
	  * Encrypt aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * aPK : a public key used for the message encryption
	  * Result : byte[] ciphered message
	  **/
	public byte[] encrypt(byte[] aMessage, PublicKey aPK){
		try{
			// get an instance of RSA Cipher
			Cipher cipher = Cipher.getInstance("RSA");
			// init the Cipher in ENCRYPT_MODE and aPK
			cipher.init(Cipher.ENCRYPT_MODE, aPK);
			// use doFinal on the byte[] and return the ciphered byte[]
			return cipher.doFinal(aMessage);
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}
	}

	/**
	  * Decrypt aMessage with the entity private key
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * Result : byte[] deciphered message
	  **/
	public byte[] decrypt(byte[] aMessage){
		try{
			// get an instance of RSA Cipher
			Cipher cipher = Cipher.getInstance("RSA");
			// init the Cipher in DECRYPT_MODE and aPK
			cipher.init(Cipher.DECRYPT_MODE, this.thePrivateKey);
			// use doFinal on the byte[] and return the deciphered byte[]
			return cipher.doFinal(aMessage);
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}

	}
}
