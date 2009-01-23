package org.pwsafe.lib.file;

import java.io.IOException;
import java.io.InputStream;

public interface PwsStorage {
	public void close() throws IOException;
	public InputStream getInputStream() throws IOException;
	/** Returns true if the save was successful */
	public boolean save(byte[] data) throws IOException;
	public PwsStorage clone(String prefix);
}
