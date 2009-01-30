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

import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.pwsafe.lib.Util;
import org.pwsafe.lib.exception.PasswordSafeException;

/**
 * A reimplementation of the BlowfishPws class to use the Bouncy Castle
 * implementation of Blowfish.
 * 
 * @author Michael Tiller
 */
public class BCBlowfishPws
{ 
	private CBCBlockCipher decipher;
	private CBCBlockCipher encipher;
	private ParametersWithIV div;
	private KeyParameter dkp;
	private ParametersWithIV eiv;
	private KeyParameter ekp;
	
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
	}

	/**
	 * Constructor, sets the initial vector to the value given.
	 * 
	 * @param bfkey      the encryption/decryption key.
	 * @param initCBCIV the initial vector.
	 * @throws PasswordSafeException 
	 */
	public BCBlowfishPws( byte[] bfkey, byte[] ivBytes )
	{
		System.out.println("bfkey = "+Util.bytesToHex(bfkey));
		BlowfishEngine tfe = new BlowfishEngine();
    	decipher = new CBCBlockCipher(tfe);
    	encipher = new CBCBlockCipher(tfe);
    	dkp = new KeyParameter(bfkey);
    	div = new ParametersWithIV(dkp, ivBytes);
    	ekp = new KeyParameter(bfkey);
    	eiv = new ParametersWithIV(ekp, ivBytes);
		decipher.init(false, div);
		encipher.init(true, eiv);
	}

	/**
	 * Decrypts <code>buffer</code> in place.
	 * 
	 * @param buffer the buffer to be decrypted.
	 * @throws PasswordSafeException 
	 */
	public void decrypt( byte[] buffer ) throws PasswordSafeException
	{
		int bs = decipher.getBlockSize();
		byte[] temp = new byte[buffer.length];
		Util.bytesToLittleEndian( buffer );

		if ((buffer.length % bs)!=0) {
			throw new PasswordSafeException("Block size must be a multiple of cipher block size ("+bs+")");
		}
		for(int i=0;i<buffer.length;i+=bs) {
			decipher.processBlock(buffer, i, temp, i);
		}
		
		Util.copyBytes(temp, buffer);
		Util.bytesToLittleEndian( buffer );
	}

	/**
	 * Encrypts <code>buffer</code> in place.
	 * 
	 * @param buffer the buffer to be encrypted.
	 * @throws PasswordSafeException 
	 */
	public void encrypt( byte[] buffer ) throws PasswordSafeException
	{
		int bs = encipher.getBlockSize();
		byte[] temp = new byte[buffer.length];
		Util.bytesToLittleEndian( buffer );

		if ((buffer.length % bs)!=0) {
			throw new PasswordSafeException("Block size must be a multiple of cipher block size ("+bs+")");
		}
		for(int i=0;i<buffer.length;i+=bs) {
			encipher.processBlock(buffer, i, temp, i);
		}
		
		Util.copyBytes(temp, buffer);
		Util.bytesToLittleEndian( buffer );
	}

	/**
	 * Sets the initial vector.
	 * 
	 * @param newCBCIV the new value for the initial vector.
	 */
	public void setCBCIV( byte[] ivBytes )
	{
		// Set the initial vector
		div = new ParametersWithIV(dkp, ivBytes);
		eiv = new ParametersWithIV(ekp, ivBytes);
		decipher.init(false, div);
		encipher.init(false, eiv);
	}

	private static byte[] zeroIV() {
		byte[] ret = new byte[8];
		for(int i=0;i<8;i++) { ret[i] = 0; }
		return ret;
	}
	
	public static byte[] makeByteKey(long key) {
		byte ivBytes[] = new byte[8];
		ByteBuffer buf = ByteBuffer.wrap(ivBytes);  
		buf.putLong(key);
		return ivBytes;
	}
}
