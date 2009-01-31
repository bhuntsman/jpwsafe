package org.pwsafe.lib.crypto;

import org.bouncycastle.crypto.digests.SHA1Digest;

public class BCSHA1 {
	private SHA1Digest sha1;
	byte[] output;
	public BCSHA1() {
		sha1 = new org.bouncycastle.crypto.digests.SHA1Digest();
		output = new byte[sha1.getDigestSize()];
	}
	public void update(byte[] bytes) {
		update(bytes, 0, bytes.length);
	}
	public void update(byte[] bytes, int offset, int length) {
		sha1.update(bytes, offset, length);		
	}
	public void finalize() {
		sha1.doFinal(output, 0);		
	}
	public byte[] getDigest() {
		return output;
	}
	public void clear() {
		sha1.reset();
	}
}
