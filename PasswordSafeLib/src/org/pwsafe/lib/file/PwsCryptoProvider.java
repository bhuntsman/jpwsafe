package org.pwsafe.lib.file;

import java.io.IOException;

import org.pwsafe.lib.exception.EndOfFileException;

public interface PwsCryptoProvider {
	/**
	 * Reads raw (undecrypted) bytes from the file.  The method attepts to read
	 * <code>bytes.length</code> bytes from the file.
	 * 
	 * @param bytes the array to be filled from the file.
	 * 
	 * @throws EndOfFileException If end of file occurs whilst reading the data.
	 * @throws IOException        If an error occurs whilst reading the file.
	 */
	public void readBytes( byte [] bytes ) throws IOException, EndOfFileException;
	
	/**
	 * Reads bytes from the file and decryps them.  <code>buff</code> may be any length provided
	 * that is a multiple of <code>getBlockSize()</code> bytes in length.
	 * 
	 * @param buff the buffer to read the bytes into.
	 * 
	 * @throws EndOfFileException If end of file has been reached.
	 * @throws IOException If a read error occurs.
	 * @throws IllegalArgumentException If <code>buff.length</code> is not an integral multiple of <code>BLOCK_LENGTH</code>.
	 */
	public void readDecryptedBytes( byte [] buff ) throws EndOfFileException, IOException;
	
	/**
	 * Writes unencrypted bytes to the file.
	 * 
	 * @param buffer the data to be written.
	 * 
	 * @throws IOException
	 */
	public void writeBytes( byte [] buffer ) throws IOException;
	
	/**
	 * Encrypts then writes the contents of <code>buff</code> to the file.
	 * 
	 * @param buff the data to be written.
	 * 
	 * @throws IOException
	 */
	public void writeEncryptedBytes( byte [] buff )	throws IOException;
}
