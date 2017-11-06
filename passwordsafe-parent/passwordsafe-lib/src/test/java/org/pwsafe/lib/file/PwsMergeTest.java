package org.pwsafe.lib.file;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Iterator;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Prepare for merge functionality.
 * 
 */
public class PwsMergeTest {

	private String origPassphrase;
	private File origFile;
	private PwsFileV3 origPwsFile;
	
	private String mergePassphrase;
	private File mergeFile; 
	private PwsFileV3 mergePwsFile;
	
	@Before
	public void setUp() throws IOException {
		
		origFile = File.createTempFile("sample3", "psafe3");
		origPassphrase = "Pa$$word";
		try {
			origPwsFile = TestUtils.createPwsFileV3(origFile.getPath(), new StringBuilder(origPassphrase));
		} catch (final IOException e) {
			throw new RuntimeException(e);
		}
		assertTrue("testsafe creation failed", origFile.exists());
		
		mergeFile = File.createTempFile("merge3", "psafe3");
		mergePassphrase = "Pazzword";
		try {
			mergePwsFile = TestUtils.createPwsFileV3(mergeFile.getPath(), new StringBuilder(mergePassphrase));
		} catch (final IOException e) {
			throw new RuntimeException(e);
		}
		assertTrue("testsafe creation failed", mergeFile.exists());
		
	}
	
	@After
	public void tearDown() {
		deletePwsFile(origFile);
		deletePwsFile(mergeFile);
	}
	
	private static void deletePwsFile(final File file) {
		if (file.exists()) {
			assertTrue("Couldn't delete testfile", file.delete());
		}
	}

	@Test
	public void testMergeSame() {
		Iterator<? extends PwsRecord> recordsToMerge = mergePwsFile.getRecords();
		while (recordsToMerge.hasNext()) {
			PwsRecord recordToMerge = recordsToMerge.next();
			Iterator<? extends PwsRecord> origRecords = origPwsFile.getRecords();
			while (origRecords.hasNext()) {
				PwsRecord origRecord = origRecords.next();
				System.out.println("toMerge: " + recordToMerge.getField(PwsFieldTypeV3.TITLE) + ", orig: " + origRecord.getField(PwsFieldTypeV3.TITLE));
				if (recordToMerge.getField(PwsFieldTypeV3.UUID).equals(origRecord.getField(PwsFieldTypeV3.UUID))) {
					System.out.println("Found same UUID" + recordToMerge.getField(PwsFieldTypeV3.UUID));
				}
				if (recordToMerge.getField(PwsFieldTypeV3.TITLE).equals(origRecord.getField(PwsFieldTypeV3.TITLE))) {
					System.out.println("Found same TITLE" + recordToMerge.getField(PwsFieldTypeV3.TITLE));
				}
			}
		}
	}

}
