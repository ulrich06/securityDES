package com.polytech.security;



import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.util.*;

public class SqueletonTripleDES{

	static public void main(String[] argv){
		
		Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);
		
		try{
	
			if(argv.length>0){
			
				// Create a TripleDES object 
				SqueletonTripleDES the3DES = new SqueletonTripleDES();
			
				if(argv[0].compareTo("-ECB")==0){
					// EBC mode
				  	// encrypt EBC mode
				  	Vector Parameters= 
					  	the3DES.encryptECB(
					  			new FileInputStream(new File(argv[1])),  	// clear text file 
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
				   	  			"DES/ECB/NoPadding"); 						// CipherName
				  	// decrypt EBC mode
				  	the3DES.decryptECB(Parameters,				 			// the 3 DES keys
				  				new FileInputStream(new File(argv[2])),  	// the encrypted file 
				   	  			new FileOutputStream(new File(argv[3])),	// the decrypted file
				   	  			"DES/ECB/NoPadding"); 		  				// CipherName
				}	
				else if(argv[0].compareTo("-CBC")==0){
					// decryption
				  	// encrypt CBC mode
				  	Vector Parameters = 
					  	the3DES.encryptCBC(
					  			new FileInputStream(new File(argv[1])),  	// clear text file 
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
					  			"DES/CBC/NoPadding"); 						// CipherName
				   	  			//"DES/CBC/PKCS5Padding"); 					// CipherName 
				  	// decrypt CBC mode	
				  	the3DES.decryptCBC(
				  				Parameters,				 					// the 3 DES keys
			  					new FileInputStream(new File(argv[2])),  	// the encrypted file 
			  					new FileOutputStream(new File(argv[3])),	// the decrypted file
				  				"DES/CBC/NoPadding"); 						// CipherName			
				  				//"DES/CBC/PKCS5Padding"); 		  			// CipherName	  
				}
			
			}
			
			else{
				System.out.println("java TripleDES -EBC clearTextFile EncryptedFile DecryptedFile");
				System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
			} 
		}catch(Exception e){
			e.printStackTrace();
			System.out.println("java TripleDES -EBC clearTextFile EncryptedFile DecryptedFile");
			System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
		}
	}

	
	/**
	 * 3DES ECB Encryption
	 */

	private Vector encryptECB(FileInputStream in, 
							FileOutputStream out, 
							String KeyGeneratorInstanceName, 
							String CipherInstanceName){
		try{
			
			// GENERATE 3 DES KEYS
			KeyGenerator kg = KeyGenerator.getInstance(KeyGeneratorInstanceName);
			
			Vector<SecretKey> skList = new Vector<SecretKey>();
			skList.add(kg.generateKey());
			skList.add(kg.generateKey());
			skList.add(kg.generateKey());
				
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR ENCRYPTION 
				// WITH THE FIRST GENERATED DES KEY
			Cipher cipher1 = Cipher.getInstance(CipherInstanceName);
			cipher1.init(Cipher.ENCRYPT_MODE, skList.get(0));
			
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
			Cipher cipher2 = Cipher.getInstance(CipherInstanceName);
			cipher2.init(Cipher.DECRYPT_MODE, skList.get(1));
			
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName 
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY
			Cipher cipher3 = Cipher.getInstance(CipherInstanceName);
			cipher3.init(Cipher.ENCRYPT_MODE, skList.get(2));

			// GET THE MESSAGE TO BE ENCRYPTED FROM IN
            // CIPHERING
            // CIPHER WITH THE FIRST KEY
            // DECIPHER WITH THE SECOND KEY
            // CIPHER WITH THE THIRD KEY

            CipherInputStream cis = new CipherInputStream(in, cipher1);
            CipherInputStream cis2 = new CipherInputStream(cis,cipher2);
            CipherInputStream cis3 = new CipherInputStream(cis2, cipher3);
            // write encrypted file
            byte[] bytes = new byte[64];
            int numBytes;
            while ((numBytes = cis3.read(bytes)) != -1) {
                out.write(bytes, 0, numBytes);
            }
            out.flush();
            out.close();
            cis.close();
            cis2.close();
            cis3.close();
			// return the DES keys list generated		
			return skList;
			
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * 3DES ECB Decryption 
	 */
	private void decryptECB(Vector Parameters, 
						FileInputStream in, 
						FileOutputStream out, 
						String CipherInstanceName){
		try{
			
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION 
				// WITH THE THIRD GENERATED DES KEY
			Cipher cipher1 = Cipher.getInstance(CipherInstanceName);
			cipher1.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(2));
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
			Cipher cipher2 = Cipher.getInstance(CipherInstanceName);
			cipher2.init(Cipher.ENCRYPT_MODE, (SecretKey) Parameters.get(1));
			// CREATE A DES CIPHER OBJECT WITH DES/ECB/PKCS5PADDING FOR ENCRYPTION
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY
			Cipher cipher3 = Cipher.getInstance(CipherInstanceName);
			cipher3.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(0));

            // WRITE THE PLAIN DATA IN OUT
            CipherOutputStream cos2 = new CipherOutputStream(out, cipher3);
            CipherOutputStream cos1 = new CipherOutputStream(cos2, cipher2);
            CipherOutputStream cos = new CipherOutputStream(cos1, cipher1);

            // GET THE ENCRYPTED DATA FROM IN
            byte[] bytes = new byte[64];
            int numBytes;
            while ((numBytes = in.read(bytes)) != -1) {
                cos.write(bytes, 0, numBytes);
            }
            cos.flush();
            cos.close();
            in.close();
			
		}catch(Exception e){
			e.printStackTrace();
		}

	}
	  
	//MATTHIEU :
	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptCBC(FileInputStream in, 
							FileOutputStream out, 
							String KeyGeneratorInstanceName, 
							String CipherInstanceName){
		try{
		
			// GENERATE 3 DES KEYS
			// GENERATE THE IV

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY

			// GET THE DATA TO BE ENCRYPTED FROM IN

			// CIPHERING
				// CIPHER WITH THE FIRST KEY
				// DECIPHER WITH THE SECOND KEY
				// CIPHER WITH THE THIRD KEY

			// WRITE THE ENCRYPTED DATA IN OUT

			// return the DES keys list generated
            // GENERATE 3 DES KEYS
           // <SecretKey>
            KeyGenerator kg = KeyGenerator.getInstance(KeyGeneratorInstanceName);

            Vector pamList = new Vector();
            pamList.add(kg.generateKey());
            pamList.add(new IvParameterSpec(new byte[8]));
            pamList.add(kg.generateKey());
            pamList.add(new IvParameterSpec(new byte[8]));
            pamList.add(kg.generateKey());
            pamList.add(new IvParameterSpec(new byte[8]));


            Cipher cipher1 = Cipher.getInstance(CipherInstanceName);
            cipher1.init(Cipher.ENCRYPT_MODE, (SecretKey) pamList.get(0),(IvParameterSpec) pamList.get(1));


            Cipher cipher2 = Cipher.getInstance(CipherInstanceName);
            cipher2.init(Cipher.DECRYPT_MODE, (SecretKey) pamList.get(2),(IvParameterSpec) pamList.get(3));


            Cipher cipher3 = Cipher.getInstance(CipherInstanceName);
            cipher3.init(Cipher.ENCRYPT_MODE,(SecretKey) pamList.get(4),(IvParameterSpec) pamList.get(5));

            CipherInputStream cis = new CipherInputStream(in, cipher1);
            CipherInputStream cis2 = new CipherInputStream(cis,cipher2);
            CipherInputStream cis3 = new CipherInputStream(cis2, cipher3);

            byte[] bytes = new byte[64];
            int numBytes;
            while ((numBytes = cis3.read(bytes)) != -1) {
                out.write(bytes, 0, numBytes);
            }
            out.flush();
            out.close();
            cis.close();
            cis2.close();
            cis3.close();

            return pamList;
			
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 3DES ECB Decryption 
	 */
	private void decryptCBC(Vector Parameters, 
						FileInputStream in, 
						FileOutputStream out, 
						String CipherInstanceName){
		try{
		
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION 
				// WITH THE THIRD GENERATED DES KEY
			
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
				
			// CREATE A DES CIPHER OBJECT WITH DES/EBC/PKCS5PADDING FOR ENCRYPTION
				// WITH CipherInstanceName
				// FOR ENCRYPTION
				// WITH THE FIRST GENERATED DES KEY
			
			// GET ENCRYPTED DATA FROM IN
			
			// DECIPHERING     
				// DECIPHER WITH THE THIRD KEY
				// 	CIPHER WITH THE SECOND KEY
				// 	DECIPHER WITH THE FIRST KEY

			// WRITE THE DECRYPTED DATA IN OUT
            // CREATE A DES CIPHER OBJECT
            // WITH CipherInstanceName
            // FOR DECRYPTION
            // WITH THE THIRD GENERATED DES KEY
            Cipher cipher1 = Cipher.getInstance(CipherInstanceName);
            cipher1.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(4),(IvParameterSpec) Parameters.get(5));

            Cipher cipher2 = Cipher.getInstance(CipherInstanceName);
            cipher2.init(Cipher.ENCRYPT_MODE, (SecretKey) Parameters.get(2),(IvParameterSpec) Parameters.get(3));

            Cipher cipher3 = Cipher.getInstance(CipherInstanceName);
            cipher3.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(0),(IvParameterSpec) Parameters.get(1));

            CipherOutputStream cos2 = new CipherOutputStream(out, cipher3);
            CipherOutputStream cos1 = new CipherOutputStream(cos2, cipher2);
            CipherOutputStream cos = new CipherOutputStream(cos1, cipher1);

            byte[] bytes = new byte[64];
            int numBytes;
            while ((numBytes = in.read(bytes)) != -1) {
                cos.write(bytes, 0, numBytes);
            }
            cos.flush();
            cos.close();
            in.close();

		}catch(Exception e){
			e.printStackTrace();
		}

	}
	  

}