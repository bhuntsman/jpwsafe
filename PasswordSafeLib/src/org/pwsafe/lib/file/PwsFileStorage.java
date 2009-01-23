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

	/** An InputStream of the file contents */
	private FileInputStream dbstream;
	
	/*
	 * Build an implementation given the filename for the underlying storage. 
	 */
	public PwsFileStorage(String filename) throws IOException {
		this.filename = filename;
	}
	
	/**
	 * Closes the stream associated with the file.
	 */
	public void close() throws IOException {
		dbstream.close();
		dbstream = null;
	}

	/**
	 * Returns the input stream associated with the file.
	 */
	public InputStream getInputStream() throws IOException {
		if (dbstream==null) {
			dbstream = new FileInputStream(filename);
		}
		return dbstream;
	}

	/**
	 * Takes the (encrypted) bytes and writes them out to the file.
	 * 
	 * This particular method takes steps to make sure that the
	 * original file is not overwritten or deleted until the
	 * new file has been successfully saved.
	 */
	public boolean save(byte[] data) throws IOException {
		System.err.println("Number of bytes to save = "+data.length);
		
		File file2		= new File( filename );
		String FilePath	= file2.getParent();
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
		OutStream.close();
		if (dbstream!=null) {
			dbstream.close();
		}
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
	}

	/**
	 * FIXME: Currently unimplemented.
	 */
	public PwsStorage clone(String prefix) {
		System.err.println("Unimplemented");
		// TODO Auto-generated method stub
		return null;
	}
	
	/**
	 * This method is *not* part of the storage interface but specific to
	 * this particular implementation.
	 * 
	 * @return Name of the file used for storage.
	 */
	public String getFilename() { return filename; }
}
