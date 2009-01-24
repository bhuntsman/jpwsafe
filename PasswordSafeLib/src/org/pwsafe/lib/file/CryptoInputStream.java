package org.pwsafe.lib.file;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import net.sourceforge.blowfishj.SHA1;

import org.pwsafe.lib.crypto.BlowfishPws;

public class CryptoInputStream extends InputStream {
	private byte [] block = new byte[16];
	private int index = 0;
	private int curBlockSize = 0;
	/* Header info */
	private byte []	randStuff = null;
	private byte []	randHash = null;
	private byte [] salt = null;
	private byte [] ipThing = null;
	
	private String passphrase;
	private InputStream rawStream;
	private BlowfishPws engine;
	public CryptoInputStream(String passphrase, InputStream stream) {
		rawStream = stream;
		this.passphrase = passphrase;
	}
	  public static int unsignedByteToInt(byte b) {
		    return (int) b & 0xFF;
		    }

	public int read() throws IOException {
		/** first time through, parse header and set up engine */
		if (salt==null) {
			randStuff = new byte[8];
			randHash = new byte[20];
			salt = new byte[20];
			ipThing = new byte[8];
			rawStream.read(randStuff);
			rawStream.read(randHash);
			rawStream.read(salt);
			rawStream.read(ipThing);
			engine = makeBlowfish(passphrase.getBytes());
			curBlockSize = rawStream.read(block);
			if (curBlockSize==-1) { return -1; } 
			engine.decrypt(block);
		}
		if (index<curBlockSize) {
			/** Get next byte in existing buffer */
			index++;
			//System.out.println("Reading in "+((int)block[index-1] & 0xff));
			return (int) block[index-1] & 0xff;
		} else {
			/** Read a new block */
			curBlockSize = rawStream.read(block);
			if (curBlockSize==-1) { return -1; }
			engine.decrypt(block);
			index = 1;
			//System.out.println("Reading in "+((int)block[0] & 0xff));
			return (int)block[0] & 0xff;
		}
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
	
	public void close() throws IOException {
		rawStream.close();
		super.close();
	}
}
