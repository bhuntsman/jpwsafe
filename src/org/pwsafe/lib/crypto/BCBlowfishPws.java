/*
 * $Id: BlowfishPws.java 317 2009-01-26 20:20:54Z ronys $
 * 
 * Copyright (c) 2008-2009 David Muller <roxon@users.sourceforge.net>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */
package org.pwsafe.lib.crypto;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.pwsafe.lib.Util;
import org.pwsafe.lib.exception.PasswordSafeException;

/**
 * An extension to the BlowfishJ.BlowfishCBC to allow it to be used for PasswordSafe. Byte 
 * order differences prevent BlowfishCBC being used directly.
 * 
 * @author Kevin Preece
 */
public class BCBlowfishPws
{ 
	private Cipher cipher;
	private IvParameterSpec iv;
	private SecretKeySpec secretKeySpec;
	
	/**
	 * Constructor, sets the initial vector to zero.
	 * 
	 * @param bfkey the encryption/decryption key.
	 * @throws PasswordSafeException 
	 */
	public BCBlowfishPws( byte[] bfkey ) throws PasswordSafeException
	{
		this(bfkey, zeroIV());
	}

	/**
	 * Constructor, sets the initial vector to the value given.
	 * 
	 * @param bfkey      the encryption/decryption key.
	 * @param lInitCBCIV the initial vector.
	 * @throws PasswordSafeException 
	 */
	public BCBlowfishPws( byte[] bfkey, long lInitCBCIV ) throws PasswordSafeException
	{
		this(bfkey, makeByteKey(lInitCBCIV));
		Cipher cipher = null;
	}

	/**
	 * Constructor, sets the initial vector to the value given.
	 * 
	 * @param bfkey      the encryption/decryption key.
	 * @param initCBCIV the initial vector.
	 * @throws PasswordSafeException 
	 */
	public BCBlowfishPws( byte[] bfkey, byte[] ivBytes ) throws PasswordSafeException
	{

		// create a SecretKeySpec from key material
		secretKeySpec = new SecretKeySpec(bfkey, "Blowfish");
		
		// get Cipher and init it for encryption
		try {
			cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding", "IAIK");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Cipher error: "+e.getMessage());
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Cipher error: "+e.getMessage());
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Cipher error: "+e.getMessage());
		}

		setCBCIV( ivBytes );
	}

	/**
	 * Decrypts <code>buffer</code> in place.
	 * 
	 * @param buffer the buffer to be decrypted.
	 * @throws PasswordSafeException 
	 */
	public void decrypt( byte[] buffer ) throws PasswordSafeException
	{
		Util.bytesToLittleEndian( buffer );

		try {
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Invalid decryption key: "+e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Invalid algorithm parameter: "+e.getMessage());
		}

		Util.bytesToLittleEndian( buffer );
	}

	/**
	 * Encrypts <code>buffer</code> in place.
	 * 
	 * @param buffer the buffer to be encrypted.
	 * @throws PasswordSafeException 
	 */
	public void encrypt( byte[] input ) throws PasswordSafeException
	{
		Util.bytesToLittleEndian( input );
        try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Invalid key: "+e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Invalid algorithm parameter: "+e.getMessage());
		}
        
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        
        int ctLength;
        
        try {
			ctLength = cipher.update(input, 0, input.length, cipherText, 0);
			ctLength += cipher.doFinal(cipherText, ctLength);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Illegal block size: "+e.getMessage());
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Short buffer: "+e.getMessage());
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new PasswordSafeException("Bad padding: "+e.getMessage());
		}
        
		Util.bytesToLittleEndian( input );
	}

	/**
	 * Sets the initial vector.
	 * 
	 * @param newCBCIV the new value for the initial vector.
	 */
	public void setCBCIV( byte[] ivBytes )
	{
		// Set the initial vector
		iv = new IvParameterSpec(ivBytes);
	}

	private static byte[] zeroIV() {
		byte[] ret = new byte[8];
		for(int i=0;i<8;i++) { ret[i] = 0; }
		return ret;
	}
	
	private static byte[] makeByteKey(long key) {
		byte ivBytes[] = new byte[8];
		ByteBuffer buf = ByteBuffer.wrap(ivBytes);  
		buf.putLong(key);
		return ivBytes;
	}
}
