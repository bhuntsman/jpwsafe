package org.pwsafe.lib.crypto;

import junit.framework.TestCase;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.pwsafe.lib.Util;
import org.pwsafe.lib.exception.PasswordSafeException;

public class BlowfishPwsTest extends TestCase {
	// This cipher text comes from baseline BlowfishPws data.
    int[] key = {0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
            0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A};
    int[] plainText = { 0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
              0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19 };
    int[] cipherText =  { 0xA4, 0x3D, 0x6E, 0x0B, 0x0F, 0xD6, 0xEF, 0xAA,
              0xBF, 0x74, 0xDE, 0x87, 0x38, 0x53, 0x91, 0x5E };
    
    int[] key32 = { 0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
            0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
            0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
            0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F };
    int[] plainText32 = { 0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
            0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6 };
    int[] cipherText32 = { 0x4F, 0x16, 0xBC, 0x11, 0x57, 0x4A, 0x9D, 0x55,
            0xA1, 0xA2, 0x33, 0xAA, 0xA8, 0x05, 0xD2, 0x5C };
    
	byte[] k16 = Util.unsignedToSigned(key);
	byte[] k32 = Util.unsignedToSigned(key32);
	
	byte[] pt16 = Util.unsignedToSigned(plainText);
	byte[] pt32 = Util.unsignedToSigned(plainText32);

	byte[] ct16 = Util.unsignedToSigned(cipherText);
	byte[] ct32 = Util.unsignedToSigned(cipherText32);
    
    public void BCDecrypt() throws PasswordSafeException {
		System.out.println("--> Testing decryption");
		BCBlowfishPws bc16 = new BCBlowfishPws(k16);
		BCBlowfishPws bc32 = new BCBlowfishPws(k32);
		
		byte[] buf16 = Util.unsignedToSigned(cipherText);
		byte[] buf32 = Util.unsignedToSigned(cipherText32);

		System.out.println("cipherText16 = "+Util.bytesToHex(buf16));
		bc16.decrypt(buf16);
		System.out.println("plainText16 = "+Util.bytesToHex(buf16));
		assertEquals(Util.bytesToHex(pt16),Util.bytesToHex(buf16));
		
		System.out.println("cipherText32 = "+Util.bytesToHex(buf32));
		bc32.decrypt(buf32);
		System.out.println("plainText32 = "+Util.bytesToHex(buf32));
		assertEquals(Util.bytesToHex(pt32),Util.bytesToHex(buf32));
    }
    public void BCEncrypt() throws PasswordSafeException {
		byte[] buf16 = null;
		byte[] buf32 = null;
		
		BCBlowfishPws bc16;
		BCBlowfishPws bc32;
		
		System.out.println("--> Testing encryption");
		bc16 = new BCBlowfishPws(k16);
		bc32 = new BCBlowfishPws(k32);
		
		buf16 = Util.unsignedToSigned(plainText);
		buf32 = Util.unsignedToSigned(plainText32);

		System.out.println("plainText16 = "+Util.bytesToHex(buf16));
		bc16.encrypt(buf16);
		System.out.println("cipherText16 = "+Util.bytesToHex(buf16));
		assertEquals(Util.bytesToHex(ct16),Util.bytesToHex(buf16));
		
		System.out.println("plainText32 = "+Util.bytesToHex(buf32));
		bc32.encrypt(buf32);
		System.out.println("cipherText32 = "+Util.bytesToHex(buf32));
		assertEquals(Util.bytesToHex(ct32),Util.bytesToHex(buf32));
    }
	public void testBCBlowfish() throws PasswordSafeException {
		System.out.println("== Testing BCBlowfishPws ==");
	
		BCEncrypt();
		BCDecrypt();
	}
	
	public void JDecrypt() {
		BlowfishPws bc16 = new BlowfishPws(k16);
		BlowfishPws bc32 = new BlowfishPws(k32);
		
		System.out.println("--> Testing decryption");
		byte[] buf16 = Util.unsignedToSigned(cipherText);
		byte[] buf32 = Util.unsignedToSigned(cipherText32);

		System.out.println("cipherText16 = "+Util.bytesToHex(buf16));
		bc16.decrypt(buf16);
		System.out.println("plainText16 = "+Util.bytesToHex(buf16));
		assertEquals(Util.bytesToHex(pt16),Util.bytesToHex(buf16));
		
		System.out.println("cipherText32 = "+Util.bytesToHex(buf32));
		bc32.decrypt(buf32);
		System.out.println("plainText32 = "+Util.bytesToHex(buf32));
		assertEquals(Util.bytesToHex(pt32),Util.bytesToHex(buf32));
	}
	
	public void runBCRoundTrip() throws PasswordSafeException {
		BCBlowfishPws ebc16 = new BCBlowfishPws(k16);
		BCBlowfishPws ebc32 = new BCBlowfishPws(k32);
		BlowfishPws ej16 = new BlowfishPws(k16);
		BlowfishPws ej32 = new BlowfishPws(k32);
		BCBlowfishPws dbc16 = new BCBlowfishPws(k16);
		BCBlowfishPws dbc32 = new BCBlowfishPws(k32);

		byte[] buf16 = new byte[64];
		Util.newRandBytes(buf16);
		byte[] orig = Util.cloneByteArray(buf16);
		byte[] j16 = Util.cloneByteArray(buf16);
		
		ebc16.encrypt(buf16);
		ej16.encrypt(j16);
		
		// Make sure the two blowfish implementations give the same
		// answer here.
		assertEquals(Util.bytesToHex(j16),Util.bytesToHex(buf16));
		
		dbc16.decrypt(buf16);
		
		assertEquals(Util.bytesToHex(orig),Util.bytesToHex(buf16));
		
		byte[] buf32 = new byte[64];
		Util.newRandBytes(buf32);
		orig = Util.cloneByteArray(buf32);
		byte[] j32 = Util.cloneByteArray(buf32);
		
		ebc32.encrypt(buf32);
		ej32.encrypt(j32);
		
		// Make sure the two blowfish implementations give the same
		// answer here.
		assertEquals(Util.bytesToHex(j32),Util.bytesToHex(buf32));
		
		dbc32.decrypt(buf32);
		
		assertEquals(Util.bytesToHex(orig),Util.bytesToHex(buf32));
	}
	
	public void runJRoundTrip() {
		BlowfishPws ej16 = new BlowfishPws(k16);
		BlowfishPws dj16 = new BlowfishPws(k16);
		BlowfishPws ej32 = new BlowfishPws(k32);
		BlowfishPws dj32 = new BlowfishPws(k32);

		byte[] buf16 = new byte[64];
		Util.newRandBytes(buf16);
		byte[] orig = Util.cloneByteArray(buf16);
		
		ej16.encrypt(buf16);
		dj16.decrypt(buf16);
		
		assertEquals(Util.bytesToHex(orig),Util.bytesToHex(buf16));
		
		byte[] buf32 = new byte[64];
		Util.newRandBytes(buf32);
		orig = Util.cloneByteArray(buf32);
		
		ej32.encrypt(buf32);
		dj32.decrypt(buf32);
		
		assertEquals(Util.bytesToHex(orig),Util.bytesToHex(buf32));
	}
	
	public void JEncrypt() {
		BlowfishPws bc16 = new BlowfishPws(k16);
		BlowfishPws bc32 = new BlowfishPws(k32);
		
		byte[] buf16 = Util.unsignedToSigned(plainText);
		byte[] buf32 = Util.unsignedToSigned(plainText32);

		System.out.println("--> Testing encryption");
		System.out.println("plainText16 = "+Util.bytesToHex(buf16));
		bc16.encrypt(buf16);
		System.out.println("cipherText16 = "+Util.bytesToHex(buf16));
		assertEquals(Util.bytesToHex(ct16),Util.bytesToHex(buf16));
		
		System.out.println("plainText32 = "+Util.bytesToHex(buf32));
		bc32.encrypt(buf32);
		System.out.println("cipherText32 = "+Util.bytesToHex(buf32));
		assertEquals(Util.bytesToHex(ct32),Util.bytesToHex(buf32));
	}
	
	public void testBlowfish() throws PasswordSafeException {
		System.out.println("== Testing BlowfishPws ==");

		JDecrypt();
		JEncrypt();
	}
	
	public void testRunTrip() throws PasswordSafeException {
		for(int i=0;i<25;i++) {
			runBCRoundTrip();
			runJRoundTrip();
		}
	}
	
	public void testFixedBareBC() {
		runBareBC(k16, pt16, ct16);
	}	
	
	public void testReversedBareBC16() {
		byte[] lept16 = Util.cloneByteArray(pt16);
		Util.bytesToLittleEndian(lept16);
		byte[] lect16 = Util.cloneByteArray(ct16);
		Util.bytesToLittleEndian(lect16);

		runBareBC(k16, lept16, lect16);
	}
	
	public void testReversedBareBC32() {
		byte[] lept32 = Util.cloneByteArray(pt32);
		Util.bytesToLittleEndian(lept32);
		System.out.println("nopt32 = "+Util.bytesToHex(pt32));
		System.out.println("lept32 = "+Util.bytesToHex(lept32));
		byte[] lect32 = Util.cloneByteArray(ct32);
		Util.bytesToLittleEndian(lect32);
		System.out.println("noct32 = "+Util.bytesToHex(ct32));
		System.out.println("lect32 = "+Util.bytesToHex(lect32));

		runBareBC(k32, lept32, lect32);
	}	
	
	public void testRandomBareBC() {
		byte[] orig = new byte[64];
		Util.newRandBytes(orig);
		runBareBC(k16, orig, null);
	}
	
	public void runBareBC(byte[] key, byte[] orig, byte[] expct) {
		CBCBlockCipher cipher = new CBCBlockCipher(new BlowfishEngine());
    	KeyParameter ekp = new KeyParameter(Util.cloneByteArray(key));

		cipher.init(true, ekp);
		
		byte[] buf16 = Util.cloneByteArray(orig);
		byte[] enc = new byte[buf16.length];
		
		System.out.println("orig  = "+Util.bytesToHex(orig));
		System.out.println("buf16 = "+Util.bytesToHex(orig));
		for(int i=0;i<orig.length;i+=8) {
			System.out.println("enc"+i+" = "+Util.bytesToHex(enc));
			cipher.processBlock(buf16, i, enc, i);
		}
		System.out.println("enc = "+Util.bytesToHex(enc));
		
		if (expct!=null) {
			System.out.println("exp = "+Util.bytesToHex(enc));
			assertEquals(Util.bytesToHex(expct), Util.bytesToHex(enc));
		}
		
		KeyParameter dkp = new KeyParameter(Util.cloneByteArray(key));
		
		buf16 = Util.cloneByteArray(enc);
		cipher = new CBCBlockCipher(new BlowfishEngine());
		cipher.init(false, dkp);
		
		byte[] dec = new byte[buf16.length];
		
		for(int i=0;i<orig.length;i+=8) {
			System.out.println("dec"+i+" = "+Util.bytesToHex(dec));
			cipher.processBlock(buf16, i, dec, i);
		}
		System.out.println("dec64 = "+Util.bytesToHex(dec));
		System.out.println("orig = "+Util.bytesToHex(orig));
		assertEquals(Util.bytesToHex(dec), Util.bytesToHex(orig));
	}
}
