package org.pwsafe.lib.crypto;

import java.security.Key;
import java.security.Provider;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Twofish implementation wrapper. Current implementation uses
 * BouncyCastle provider.
 * 
 * @author Glen Smith
 */
public class TwofishPws {
    
    private static Provider provider = new BouncyCastleProvider();
    
    public static Cipher getCipher(byte[] key, boolean encrypting, boolean blockMode) {

        
        try {
        	String algo = "BLOWFISH/" + (blockMode ? "ECB" : "CBC") + "/NoPadding"; 
        	KeySpec ks = new SecretKeySpec(key, algo); 
            Cipher c = Cipher.getInstance(algo,provider);
            c.init(encrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, (Key) ks);
            return c;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

}
