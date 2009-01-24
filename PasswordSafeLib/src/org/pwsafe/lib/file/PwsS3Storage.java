package org.pwsafe.lib.file;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import com.amazonaws.s3.S3;
import com.amazonaws.s3.S3Object;
import com.sun.org.apache.xml.internal.security.utils.Base64;

/**
 * This is an implementation of the storage interface that uses S3
 * as the backend.
 * 
 * @author mtiller
 *
 */
public class PwsS3Storage implements PwsStorage {
	/**
	 * A helper class to hold the Amazon S3 credentials.  This
	 * will probably be refactored as the handling of this
	 * information is improved.
	 * 
	 * @author mtiller
	 *
	 */
	public static class Credentials {
		String keyId;
		String secretKey;
		public Credentials(String id, String secret) {
			keyId = id;
			secretKey = secret;
		}
	}
	
	/**
	 * This object provides the interface to S3.
	 */
	private S3 s3;
	
	/** The name of the "bucket" where the information will be stored. */
	private String bucket;
	
	/** The name of the filename in the bucket. */
	private String filename;
	
	/** The InputStream providing the bytes */
	private InputStream dbstream;
	
	private PwsCryptoProvider crypto;
	
	/**
	 * Constructs an instance of an Amazon S3 storage provider.
	 * @param bucket The bucket name
	 * @param filename The filename to store the information in
	 * @param credentials The access credentials
	 */
	public PwsS3Storage(PwsCryptoProvider crypto, String bucket, String filename, Credentials credentials) {
		this.crypto = crypto;
		this.bucket = bucket;
		this.filename = filename;
		/** Note the use of HTTPS in the connection. */
		s3 = new S3( S3.HTTPS_URL, credentials.keyId, credentials.secretKey );
	}

	/**
	 * This method grabs the data from S3 (in one shot)
	 * and then constructs a ByteArrayInputStream for
	 * use at the PwsFile level.
	 *
	 */
	public byte[] load() throws IOException {
		try {
			/* Get the S3 object */
			S3Object obj = s3.getObject(bucket, filename);
			/* Grab the associated data */
			String data = obj.getData();
			/* Decode the string into bytes */
			byte[] bytes = Base64.decode(data.getBytes());
			return bytes;
		} catch (Exception e) {
			e.printStackTrace(System.err);
			throw new IOException("Unable to load: "+e.getMessage());
		}
	}

	/**
	 * This method saves all the data back to S3 (in one
	 * shot).
	 */
	public boolean save(byte[] bytes) {
		/* Turn the bytes into a String for S3 */
		String data = Base64.encode(bytes);
		try {
			/* Upload the S3 object */
			s3.putObjectInline(bucket, filename, data);
			return true;
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return false;			
		}
	}
	
	/**
	 * This method is not a part of the storage interface.  It opens
	 * a file that contains information about the S3 account (bucket,
	 * access credentials) and then creates an instance of the S3 storage
	 * class.
	 * 
	 * The file format is (at the moment) just bucket, access key, secret key
	 * (each on a different line).
	 * 
	 * @param filename The file containing the S3 information. 
	 * @return An instance of the S3 storage class.
	 * @throws IOException
	 */
	public static PwsS3Storage fromFile(PwsCryptoProvider crypto, String filename) throws IOException {
		FileInputStream fin = new FileInputStream(filename);
		InputStreamReader isr = new InputStreamReader(fin);
		BufferedReader br = new BufferedReader(isr);
		String bucket = br.readLine();
		String id = br.readLine();
		String secret = br.readLine();
		Credentials credentials = new Credentials(id, secret);
		PwsS3Storage pss = new PwsS3Storage(crypto, bucket, "pwsafe_data", credentials);
		return pss;
	}
}
