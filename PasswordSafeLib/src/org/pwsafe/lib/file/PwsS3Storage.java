package org.pwsafe.lib.file;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

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
	public static class AccountDetails {
		String bucket;
		String keyId;
		String secretKey;
		public AccountDetails(String bucket, String id, String secret) {
			this.bucket = bucket;
			keyId = id;
			secretKey = secret;
		}
	}
	
	/**
	 * This object provides the interface to S3.
	 */
	private S3 s3;

	/** These are the details about the amazon account required to access the
	 * S3 storage.  These can either be read from a local file or entered by
	 * the user in the case where the password safe is being initialized.
	 */
	private AccountDetails account;
	
	/** The name of the filename in the bucket. */
	private String filename;
	
	/** The InputStream providing the bytes */
	private InputStream dbstream;
	
	private PwsCryptoProvider crypto;
	
	/**
	 * Constructs an instance of an Amazon S3 storage provider.
	 * @param bucket The bucket name
	 * @param filename The filename the account information is stored in (if it exists) or
	 * the file to write it to if the storage is initialized.
	 * @param account The bucket name and access credentials for the S3 account.  These are
	 * only required if a new storage area is being initialized.  Otherwise, they are
	 * read from the specified file.
	 */
	public PwsS3Storage(PwsCryptoProvider crypto, String filename, AccountDetails acc) throws IOException {
		this.crypto = crypto;
		this.filename = filename;
		File f = new File(filename);
		if (f.exists()) {
			this.account = new AccountDetails(null, null, null);
			FileInputStream fin = new FileInputStream(filename);
			InputStreamReader isr = new InputStreamReader(fin);
			BufferedReader br = new BufferedReader(isr);
			account.bucket = br.readLine();
			account.keyId = br.readLine();
			account.secretKey = br.readLine();
			/** Note the use of HTTPS in the connection. */
			s3 = new S3( S3.HTTPS_URL, account.keyId, account.secretKey );
		} else {
			this.account = acc;
			if (acc!=null && acc.bucket!=null && acc.keyId!=null && acc.secretKey!=null) {
				/** Note the use of HTTPS in the connection. */
				s3 = new S3( S3.HTTPS_URL, account.keyId, account.secretKey );
				/** TODO: Check that the S3 credentials are valid somehow before
				 * writing the file.
				 */
				/** FIXME: need to create the bucket */
				FileOutputStream fin = new FileOutputStream(filename);
				OutputStreamWriter osw = new OutputStreamWriter(fin);
				osw.write(account.bucket+"\n");
				osw.write(account.keyId+"\n");
				osw.write(account.secretKey+"\n");
			} else {
				// FIXME: What to do?
				/* Nothing can be done...throw exception? */
				s3 = null;
			}
		}
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
			S3Object obj = s3.getObject(account.bucket, filename);
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
			s3.putObjectInline(account.bucket, filename, data);
			return true;
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return false;			
		}
	}
}
