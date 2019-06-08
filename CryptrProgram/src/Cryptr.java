import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 *               Cryptr
 *
 * Cryptr is a java encryption toolset
 * that can be used to encrypt/decrypt files
 * and keys locally, allowing for files to be
 * shared securely over the world wide web
 *
 * Cryptr provides the following functions:
 *	 1. Generating a secret key
 *   2. Encrypting a file with a secret key
 *   3. Decrypting a file with a secret key
 *   4. Encrypting a secret key with a public key
 *   5. Decrypting a secret key with a private key
 *
 */

public class Cryptr {


	/**
	 * Generates an 128-bit AES secret key and writes it to a file
	 *
	 * @param  secKeyFile    name of file to store secret key
	 */
	static void generateKey(String secKeyFile) throws Exception {

		// Generate the secret key..
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom = new SecureRandom();
		int bitSize = 128;	
		keyGenerator.init(bitSize, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();
		
		// Write secret key to a secKeyFile...
		try (FileOutputStream out = new FileOutputStream(secKeyFile)) {
			out.write(secretKey.getEncoded());
		}
		
	}


	/**
	 * Extracts secret key from a file, generates an
	 * initialization vector, uses them to encrypt the original
	 * file, and writes an encrypted file containing the initialization
	 * vector followed by the encrypted file data
	 *
	 * @param  originalFile    name of file to encrypt
	 * @param  secKeyFile      name of file storing secret key
	 * @param  encryptedFile   name of file to write iv and encrypted file data
	 * @throws IOException 
	 */
	static void encryptFile(String originalFile, String secKeyFile, String encryptedFile) throws Exception {
		
		//Load secret key from secKeyFile
		byte[] bytes = Files.readAllBytes(Paths.get(secKeyFile));
		SecretKeySpec secretKey = new SecretKeySpec(bytes, "AES");
		
		//Generate an initialization vector
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv =  new byte[128/8];
		randomSecureRandom.nextBytes(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		
		//Create the cipher object to encrypt the file
		Cipher ciph = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ciph.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		
		//Use created cipher object to encrypt the string in the originalFile
		try (FileInputStream in = new FileInputStream(originalFile);
			FileOutputStream out = new FileOutputStream(encryptedFile)) {
			
			out.write(iv);
			
	        byte[] ibuf = new byte[1024];
	        int len;
	        while ((len = in.read(ibuf)) != -1) {
	        	byte[] obuf = ciph.update(ibuf, 0, len);
	            	if ( obuf != null ) out.write(obuf);
	            }
	            byte[] obuf = ciph.doFinal();
	            if ( obuf != null ) out.write(obuf);
	    }
				
	}


	/**
	 * Extracts the secret key from a file, extracts the initialization vector
	 * from the beginning of the encrypted file, uses both secret key and
	 * initialization vector to decrypt the encrypted file data, and writes it to
	 * an output file
	 *
	 * @param  encryptedFile    name of file storing iv and encrypted data
	 * @param  secKeyFile	    name of file storing secret key
	 * @param  outputFile       name of file to write decrypted data to
	 * @throws Exception 
	 */
	static void decryptFile(String encryptedFile, String secKeyFile, String outputFile) throws Exception {

		byte[] iv = new byte[16];
		IvParameterSpec ivspec;
		
		//load the secret key from secKeyFile
		byte[] secKeyBytes = Files.readAllBytes(Paths.get(secKeyFile));
		SecretKeySpec secretKey = new SecretKeySpec(secKeyBytes, "AES");		
		
		
		//read bytes into the initialization vector
		try (FileInputStream in = new FileInputStream(encryptedFile); 
			FileOutputStream out = new FileOutputStream(outputFile)) {
						
			in.read(iv);
			ivspec = new IvParameterSpec(iv);
		
			//generate the cipher for decryption
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			
            byte[] ibuf = new byte[1024];
            int len;
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = ci.update(ibuf, 0, len);
                if ( obuf != null ) out.write(obuf);
            }
            byte[] obuf = ci.doFinal();
            if ( obuf != null ) out.write(obuf);
        }
		
	}
		
	


	/**
	 * Extracts secret key from a file, encrypts a secret key file using
     * a public Key (*.der) and writes the encrypted secret key to a file
	 *
	 * @param  secKeyFile    name of file holding secret key
	 * @param  pubKeyFile    name of public key file for encryption
	 * @param  encKeyFile    name of file to write encrypted secret key
	 * @throws Exception 
	 */
	static void encryptKey(String secKeyFile, String pubKeyFile, String encKeyFile) throws Exception {
		
		//get publicKey
		byte[] pubBytes = Files.readAllBytes(Paths.get(pubKeyFile));
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pk = kf.generatePublic(publicKeySpec);
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pk);

		try (FileInputStream in = new FileInputStream(secKeyFile);
			 FileOutputStream out = new FileOutputStream(encKeyFile)) {
		
			byte[] ibuf = new byte[1024];
		    int len;
		    while ((len = in.read(ibuf)) != -1) {
		        byte[] obuf = cipher.update(ibuf, 0, len);
		        if ( obuf != null ) out.write(obuf);
		    }
		    byte[] obuf = cipher.doFinal();
		    if ( obuf != null ) out.write(obuf);
		}
		
	}


	/**
	 * Decrypts an encrypted secret key file using a private Key (*.der)
	 * and writes the decrypted secret key to a file
	 *
	 * @param  encKeyFile       name of file storing encrypted secret key
	 * @param  privKeyFile      name of private key file for decryption
	 * @param  secKeyFile       name of file to write decrypted secret key
	 * @throws Exception 
	 */
	static void decryptKey(String encKeyFile, String privKeyFile, String secKeyFile) throws Exception {

		//get the private Key		
		byte[] privKeyBytes = Files.readAllBytes(Paths.get(privKeyFile));
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = kf.generatePrivate(ks);
			
		
		//Decrypt encKeyFile
		Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		ci.init(Cipher.DECRYPT_MODE, privateKey);
		
		try (FileInputStream in = new FileInputStream(encKeyFile);
			 FileOutputStream out = new FileOutputStream(secKeyFile)) {
					 
			byte[] ibuf = new byte[1024];
			int len;
			while ((len = in.read(ibuf)) != -1) {
				byte[] obuf = ci.update(ibuf, 0, len);
				if ( obuf != null ) out.write(obuf);
			}
			byte[] obuf = ci.doFinal();
			if ( obuf != null ) out.write(obuf);
		}
		
	}


	/**
	 * Main Program Runner
	 */
	public static void main(String[] args) throws Exception{

		String func;

		if(args.length < 1) {
			func = "";
		} else {
			func = args[0];
		}

		switch(func)
		{
			case "generatekey":
				if(args.length != 2) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr generatekey <key output file>");
					break;
				}
				System.out.println("Generating secret key and writing it to " + args[1]);
				generateKey(args[1]);
				break;
			case "encryptfile":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
					break;
				}
				System.out.println("Encrypting " + args[1] + " with key " + args[2] + " to "  + args[3]);
				encryptFile(args[1], args[2], args[3]);
				break;
			case "decryptfile":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
					break;
				}
				System.out.println("Decrypting " + args[1] + " with key " + args[2] + " to " + args[3]);
				decryptFile(args[1], args[2], args[3]);
				break;
			case "encryptkey":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file>");
					break;
				}
				System.out.println("Encrypting key file " + args[1] + " with public key file " + args[2] + " to " + args[3]);
				encryptKey(args[1], args[2], args[3]);
				break;
			case "decryptkey":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
					break;
				}
				System.out.println("Decrypting key file " + args[1] + " with private key file " + args[2] + " to " + args[3]);
				decryptKey(args[1], args[2], args[3]);
				break;
			default:
				System.out.println("Invalid Arguments.");
				System.out.println("Usage:");
				System.out.println("  Cryptr generatekey <key output file>");
				System.out.println("  Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
				System.out.println("  Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
				System.out.println("  Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file> ");
				System.out.println("  Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
		}

		System.exit(0);

	}

}
