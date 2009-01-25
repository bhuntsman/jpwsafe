package org.pwsafe.lib.file;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import junit.framework.TestCase;

import org.pwsafe.lib.file.PwsS3Storage.AccountDetails;

public class S3Tests extends TestCase {
	public void testCreateNew() throws Exception {
		String password = "Amazon";
		PwsFileV3 file = (PwsFileV3) PwsFileFactory.newFile();
		file.setPassphrase(password);
		for (int i = 0; i < 1000; i++) {
			if (i%1 == 0) { System.out.print("."); }
			PwsRecordV3 v3 = (PwsRecordV3) file.newRecord();
			
            v3.setField(new PwsStringUnicodeField(PwsRecordV3.GROUP , "group" + i%10));
            v3.setField(new PwsStringUnicodeField(PwsRecordV3.TITLE , "title" + i));
            v3.setField(new PwsStringUnicodeField(PwsRecordV3.USERNAME , "user"+i));
            v3.setField(new PwsStringUnicodeField(PwsRecordV3.PASSWORD , "pw" + i));
            v3.setField(new PwsStringUnicodeField(PwsRecordV3.NOTES , "notes"+i));
			file.add(v3);
		}
		System.out.println();
		
		File f = new File("news3.ps");
		System.out.println("Check to see if "+f.getAbsolutePath()+" exists");
		if (f.exists()) {
			assertTrue(f.delete());
			assertFalse(f.exists());
		}
		AccountDetails details = new AccountDetails("createnew", "0QBPYR8QEGBG4ACGV502", "jSne2F6zupJWEmcv35ygGyHNmHUADLrzDaWDlgo2");
		
		/* First try to create the storage without S3 details.  This should throw an exception  */
		try {
			file.setStorage(new PwsS3Storage("news3.ps3", null, password));
			/* If you get a failure here, make sure to delete news3.ps3 in the project
			 * dir and re-run the test.  I've tried everything I can think of here to
			 * do that automatically, but it doesn't seem to work?!?
			 */
			fail("Failed to throw exception");
		} catch (IOException e) {
			/* Good */
		}
		
		/* Try again... */
		file.setStorage(new PwsS3Storage("news3.ps3", details, password));
		file.save();
		System.out.println("Wrote records: " + file.getRecordCount());
		file.close();

		/** Should be able to open it without providing details */
		PwsFileV3 file2 = new PwsFileV3(new PwsS3Storage("news3.ps3", null, password), password);
		file2.readAll();
		System.out.println("Read records: " + file2.getRecordCount());
		
		PwsFile file3 = PwsFileFactory.loadFile("news3.ps3", password);
		//file3.readAll();
		System.out.println("Read records (again): " + file3.getRecordCount());
		
		file.close();
		file2.close();
		file3.close();
		
		f = new File("news3.ps");
		if (f.exists()) {
//			assertTrue(f.delete());
//			assertFalse(f.exists());
		}
	}
	public void testReadExisiting() {
		System.out.println("read existing");
	}
	public void testCryptoS3() throws Exception {
		String filename = "testReadWrite.ps3";
		String passphrase = "Amazon";
		File f = new File(filename);
		if (f.exists()) {
			assertTrue(f.delete());
			assertFalse(f.exists());
		}
		FileOutputStream fos = new FileOutputStream(filename);
		CryptoOutputStream cos = new CryptoOutputStream(passphrase, fos);
		String word1 = "bucket";
		String word2 = "accessKey";
		String word3 = "secretKey";

		if (false) {
			OutputStreamWriter osw = new OutputStreamWriter(cos);
			osw.write(word1+"\n");
			osw.write(word2+"\n");
			osw.write(word3+"\n");
			cos.close();
		} else {
			String output = word1+"\n"+word2+"\n"+word3+"\n\n";
			byte[] bytes = output.getBytes();
			cos.write(bytes);	
			cos.close();
		}
		
		FileInputStream fin;
		CryptoInputStream cis;
		
//		fin = new FileInputStream(filename);
//		cis = new CryptoInputStream(passphrase, fin);
//		
//		int b;
//		for(b=cis.read();b!=-1;b=cis.read()) {
//			System.out.println((char)b);
//		}
		
		fin = new FileInputStream(filename);
		cis = new CryptoInputStream(passphrase, fin);
		InputStreamReader isr = new InputStreamReader(cis);
		BufferedReader br = new BufferedReader(isr);
		String bucket = br.readLine();
		System.out.println("Bucket = "+bucket);
		assertEquals(word1, bucket);
	    String keyId = br.readLine();
	    System.out.println("keyId = "+keyId);
	    assertEquals(word2, keyId);
	    String secretKey = br.readLine();
	    System.out.println("secretKey = "+secretKey);
	    assertEquals(word3, secretKey);
	    cis.close();
	}
}
