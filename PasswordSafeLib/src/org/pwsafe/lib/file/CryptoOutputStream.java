package org.pwsafe.lib.file;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.sourceforge.blowfishj.SHA1;

import org.pwsafe.lib.Util;
import org.pwsafe.lib.crypto.BlowfishPws;

public class CryptoOutputStream extends OutputStream {
	private byte [] block = new byte[16];
	private int index = 0;
	private int curBlockSize = 0;
	/* Header info */
	private byte []	randStuff = null;
	private byte []	randHash = null;
	private byte [] salt = null;
	private byte [] ipThing = null;
	
	private String passphrase;
	private OutputStream rawStream;
	private BlowfishPws engine;
	public CryptoOutputStream(String passphrase, OutputStream stream) {
		rawStream = stream;
		this.passphrase = passphrase;
	}
	/**
	 * Constructs and initialises the blowfish encryption routines ready to decrypt or
	 * encrypt data.
	 * 
	 * @param passphrase
	 * 
	 * @return A properly initialised {@link BlowfishPws} object.
	 */
	private BlowfishPws makeBlowfish( byte [] passphrase )
	{
		SHA1	sha1;
		
		sha1 = new SHA1();

		sha1.update( passphrase, 0, passphrase.length );
		sha1.update( salt, 0, salt.length );
		sha1.finalize();

		return new BlowfishPws( sha1.getDigest(), ipThing );
	}
	private void initialize() throws IOException {
		randStuff = new byte[8];
		randHash = new byte[20];
		salt = new byte[20];
		ipThing = new byte[8];
		Util.newRandBytes(randStuff);
		byte [] temp = Util.cloneByteArray( randStuff, 10 );
		randHash = PwsFileFactory.genRandHash( passphrase, temp );
		Util.newRandBytes(salt);
		Util.newRandBytes(ipThing);
		engine = makeBlowfish(passphrase.getBytes());
		rawStream.write(randStuff);
		rawStream.write(randHash);
		rawStream.write(salt);
		rawStream.write(ipThing);
	}
	public void close() throws IOException {
		if (salt==null) initialize();
		for(;index<16;index++) { block[index] = 0; }
		index = 0;
		engine.encrypt(block);
		rawStream.write(block);
		//System.out.println("Wrote block");
		rawStream.close();
		super.close();
	}
	public void write(int b) throws IOException {
		System.out.println("Writing out "+b);
		/** first time through, parse header and set up engine */
		if (salt==null) initialize();
		if (index==16) {
			engine.encrypt(block);
			//System.out.println("Wrote block");
			rawStream.write(block);
			index = 0;
		}
		block[index] = (byte)b;
		index++;
	}
}
