/*
 * $Id: PwsFileHeader.java 307 2004-02-27 23:11:59 +0000 (Fri, 27 Feb 2004) preecek $
 * 
 * This file is provided under the standard terms of the Artistic Licence.  See the
 * LICENSE file that comes with this package for details.
 */
package org.pwsafe.lib.file;

import java.io.IOException;

import org.pwsafe.lib.Log;
import org.pwsafe.lib.Util;
import org.pwsafe.lib.exception.EndOfFileException;

/**
 * This class encapsulates the header fields of a PasswordSafe database.  The header comprises:
 * </p><p>
 * <tt>
 * <pre> +--------+-----------+-----------------------------------------------+
 * | Length | Name      | Description                                   |
 * +--------+-----------+-----------------------------------------------+
 * |      8 | tag       | PWS3 tag                                      |
 * |     32 | salt      | Salt                                          |
 * |      4 | iter      | number of iterations                          |
 * |     16 | b1        | key material                                  |
 * |     16 | b2        | key material                                  |
 * |     16 | b3        | key material                                  |
 * |     16 | b6        | key material                                  |
 * |     16 | IV        | twofish IV                                    |  
 * +--------+-----------+-----------------------------------------------+</pre>
 * </tt>
 * </p>
 * 
 * @author Glen Smith (based on the work of Kevin Preece)
 */
public class PwsFileHeaderV3 
{
	private static final Log LOG = Log.getInstance(PwsFileHeaderV3.class.getPackage().getName());

	private byte [] tag 		= new byte[4];
	private byte [] salt		= new byte[32];
	private byte [] iter		= new byte[4];
	private byte [] password	= new byte[32];
	private byte [] b1 			= new byte[16];
	private byte [] b2 			= new byte[16];
	private byte [] b3 			= new byte[16];
	private byte [] b4 			= new byte[16];
	private byte [] IV 			= new byte[16];
	

	/**
	 * Creates an empty file header.
	 */
	PwsFileHeaderV3()
	{
	}

	/**
	 * Constructs the PasswordSafe file header by reading the header data from <code>file</code>.
	 * 
	 * @param file the file to read the header from.
	 * 
	 * @throws IOException        If an error occurs whilst reading from the file.
	 * @throws EndOfFileException If end of file is reached before reading all the data.
	 */
	public PwsFileHeaderV3( PwsFile file )
	throws IOException, EndOfFileException
	{
		file.readBytes( tag );
		file.readBytes( salt );
		file.readBytes( iter );
		file.readBytes( password );
		file.readBytes( b1 );
		file.readBytes( b2 );
		file.readBytes( b3 );
		file.readBytes( b4 );
		file.readBytes( IV );
	}

	/**
	 * Gets a copy of Tag.
	 * 
	 * @return A copy of Tag
	 */
	public byte [] getTag()
	{
		return Util.cloneByteArray( tag );
	}

	/**
	 * Gets a copy of Salt.
	 * 
	 * @return A copy of Salt
	 */
	public byte [] getSalt()
	{
		return Util.cloneByteArray( salt );
	}

	/**
	 * Gets a copy of Iterations.
	 * 
	 * @return A copy of Iterations
	 */
	public byte [] getIter()
	{
		return Util.cloneByteArray( iter );
	}
	
	/**
	 * Gets a copy of the stretched password.
	 * 
	 * @return A copy of the streched password
	 */
	public byte [] getPassword() {
		return Util.cloneByteArray(password);
	}

	/**
	 * Gets a copy of Salt.
	 * 
	 * @return a copy of Salt.
	 */
	public byte [] getB1()
	{
		return Util.cloneByteArray( b1 );
	}
	
	/**
	 * Gets a copy of Salt.
	 * 
	 * @return a copy of Salt.
	 */
	public byte [] getB2()
	{
		return Util.cloneByteArray( b2 );
	}
	
	/**
	 * Gets a copy of Salt.
	 * 
	 * @return a copy of Salt.
	 */
	public byte [] getB3()
	{
		return Util.cloneByteArray( b3 );
	}
	
	/**
	 * Gets a copy of Salt.
	 * 
	 * @return a copy of Salt.
	 */
	public byte [] getB4()
	{
		return Util.cloneByteArray( b4 );
	}
	
	/**
	 * Gets a copy of IV.
	 * 
	 * @return a copy of IV.
	 */
	public byte [] getIV()
	{
		return Util.cloneByteArray( IV );
	}

	/**
	 * Write the header to the file.
	 * 
	 * @param file the file to write the header to.
	 * 
	 * @throws IOException
	 */
	public void save( PwsFile file )
	throws IOException
	{
		LOG.enterMethod( "PwsFileHeader.save" );

		update( file.getPassphrase() );
		
		file.writeBytes( tag );
		file.writeBytes( salt );
		file.writeBytes( iter );
		file.writeBytes( b1 );
		file.writeBytes( b2 );
		file.writeBytes( b3 );
		file.writeBytes( b4 );
		file.writeBytes( IV );

		LOG.leaveMethod( "PwsFileHeader.save" );
	}

	/**
	 * Updates the header ready for saving.
	 * 
	 * @param passphrase the passphrase to be used to encrypt the database.
	 */
	private void update( String passphrase )
	{
		LOG.enterMethod( "PwsFileHeader.update" );

		byte	temp[];

//		for ( int ii = 0; ii < RandStuff.length; ++ii )
//		{
//			RandStuff[ii] = Util.newRand();
//		}
//		temp		= Util.cloneByteArray( RandStuff, 10 );
//		RandHash	= PwsFileFactory.genRandHash( passphrase, temp );
//		
//		for ( int ii = 0; ii < Salt.length; ++ii )
//		{
//			Salt[ii] = Util.newRand();
//		}
//		
//		for ( int ii = 0; ii < IpThing.length; ++ii )
//		{
//			IpThing[ii] = Util.newRand();
//		}

		LOG.leaveMethod( "PwsFileHeader.update" );
	}
}
