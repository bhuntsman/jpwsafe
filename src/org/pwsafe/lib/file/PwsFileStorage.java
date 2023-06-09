package org.pwsafe.lib.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.pwsafe.lib.I18nHelper;
import org.pwsafe.lib.Log;

/**
 * An implementation of the PwsStorage class that reads and writes to files.
 * @author mtiller
 *
 */
public class PwsFileStorage implements PwsStorage {
	/**
	 * An object for logging activity in this class.
	 */
	private static final Log LOG = Log.getInstance(PwsFileStorage.class.getPackage().getName());

	/** The filename used for storage */
	private String filename;
	
	/*
	 * Build an implementation given the filename for the underlying storage. 
	 */
	public PwsFileStorage(String filename) throws IOException {
		this.filename = filename;
	}
	
	/** Grab all the bytes in the file */
	public byte[] load() throws IOException {
		File file = new File(filename);
        InputStream is = new FileInputStream(filename);
        
        // Get the size of the file
        long length = file.length();
    
        if (length > Integer.MAX_VALUE) {
            // File is too large
        }
    
        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];
    
        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
               && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
            offset += numRead;
        }
    
        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file "+file.getName());
        }
    
        // Close the input stream and return bytes
        is.close();
        return bytes;
	}

	/**
	 * Takes the (encrypted) bytes and writes them out to the file.
	 * 
	 * This particular method takes steps to make sure that the
	 * original file is not overwritten or deleted until the
	 * new file has been successfully saved.
	 */
	public boolean save(byte[] data) {
		try {
			LOG.debug1("Number of bytes to save = "+data.length);
			LOG.debug1("Original file: "+filename);

			File file2		= new File( filename );
			if (!file2.exists()) {
				/* Original file doesn't exisit, just go ahead and write it
				 * (no backup, temp files needed).
				 */
				OutputStream OutStream	= new FileOutputStream( filename );

				OutStream.write(data);
				OutStream.close(); // TODO: needs a finally
				return true;
			}
			LOG.debug1("Original file path: "+file2.getAbsolutePath());
			File dir = file2.getCanonicalFile().getParentFile();
			if (dir==null) {
				LOG.error("Couldn't find the parent directory for: "+file2.getAbsolutePath());
				return false;
			}
			String FilePath	= dir.getAbsolutePath();
			String FileName	= file2.getName();

			File oldFile		= new File( FilePath, FileName );
			File bakFile		= new File( FilePath, FileName + "~" );

			if ( bakFile.exists() )
			{	
				if ( !bakFile.delete() )
				{
					LOG.error( I18nHelper.getInstance().formatMessage("E00012", new Object [] { bakFile.getCanonicalPath() } ) );
					// TODO Throw an exception here
					return false;
				}
			}

			File tempFile	= File.createTempFile( "pwsafe", null, new File(FilePath) );
			OutputStream OutStream	= new FileOutputStream( tempFile );

			OutStream.write(data);
			OutStream.close(); // TODO: needs a finally

			if ( oldFile.exists() )
			{
				if ( !oldFile.renameTo( bakFile ) )
				{
					LOG.error( I18nHelper.getInstance().formatMessage("E00011", new Object [] { tempFile.getCanonicalPath() } ) );
					// TODO Throw an exception here?
					return false;
				}
				LOG.debug1( "Old file successfully renamed to " + bakFile.getCanonicalPath() );
			}

			if ( tempFile.renameTo( oldFile ) )
			{

				LOG.debug1( "Temp file successfully renamed to " + oldFile.getCanonicalPath() );
				return true;
			}
			else
			{
				LOG.error( I18nHelper.getInstance().formatMessage("E00010", new Object [] { tempFile.getCanonicalPath() } ) );
				// TODO Throw an exception here?
				return false;
			}
		} catch(Exception e) {
			LOG.error(e.getMessage());
			return false;
		}
	}
	
	/**
	 * This method is *not* part of the storage interface but specific to
	 * this particular implementation.
	 * 
	 * @return Name of the file used for storage.
	 */
	public String getFilename() { return filename; }
	
	public void setPassphrase(String passphrase) {
		/* Do nothing since there is no additional enrypted information associated
		 * with this storage mechanism
		 */
	}
}
