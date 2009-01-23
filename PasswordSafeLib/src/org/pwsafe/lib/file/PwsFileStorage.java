package org.pwsafe.lib.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.pwsafe.lib.I18nHelper;
import org.pwsafe.lib.Log;

public class PwsFileStorage implements PwsStorage {
	private static final Log LOG = Log.getInstance(PwsFileStorage.class.getPackage().getName());
	
	private String filename;
	private FileInputStream dbstream;
	public PwsFileStorage(String filename) throws IOException {
		this.filename = filename;
	}
	public void close() throws IOException {
		dbstream.close();
		dbstream = null;
	}

	public InputStream getInputStream() throws IOException {
		if (dbstream==null) {
			dbstream = new FileInputStream(filename);
		}
		return dbstream;
	}

	public boolean save(byte[] data) throws IOException {
		System.err.println("Number of bytes to save = "+data.length);
		
		File file2		= new File( filename );
		String FilePath	= file2.getParent();
		String FileName	= file2.getName();
		
		File oldFile		= new File( FilePath, FileName );
		File bakFile		= new File( FilePath, FileName + "~" );

		LOG.info("oldFile = "+oldFile.getAbsolutePath());
		LOG.info("bakFile = "+bakFile.getAbsolutePath());
		if ( bakFile.exists() )
		{	
			if ( !bakFile.delete() )
			{
				LOG.info("Couldn't get rid of bak file");
				LOG.error( I18nHelper.getInstance().formatMessage("E00012", new Object [] { bakFile.getCanonicalPath() } ) );
				// TODO Throw an exception here
				return false;
			}
		}

		File tempFile	= File.createTempFile( "pwsafe", null, new File(FilePath) );
		LOG.info("tempFile = "+tempFile.getAbsolutePath());
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
				LOG.info("Failed to rename old file");
				LOG.error( I18nHelper.getInstance().formatMessage("E00011", new Object [] { tempFile.getCanonicalPath() } ) );
				// TODO Throw an exception here?
				return false;
			}
			LOG.debug1( "Old file successfully renamed to " + bakFile.getCanonicalPath() );
		}

		if ( tempFile.renameTo( oldFile ) )
		{

			LOG.debug1( "Temp file successfully renamed to " + oldFile.getCanonicalPath() );
			LOG.info("Successfully saved to "+oldFile.getAbsolutePath());
			return true;
		}
		else
		{
			LOG.info("Failed to rename tmp file");
			LOG.error( I18nHelper.getInstance().formatMessage("E00010", new Object [] { tempFile.getCanonicalPath() } ) );
			// TODO Throw an exception here?
			return false;
		}
	}

	public PwsStorage clone(String prefix) {
		System.err.println("Unimplemented");
		// TODO Auto-generated method stub
		return null;
	}
	public String getFilename() { return filename; }
}
