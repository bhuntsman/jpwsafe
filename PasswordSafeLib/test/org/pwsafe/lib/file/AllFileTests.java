package org.pwsafe.lib.file;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllFileTests {

	public static Test suite() {
		TestSuite suite = new TestSuite("Test for org.pwsafe.lib.file");
		//$JUnit-BEGIN$
		suite.addTestSuite(PwsFileV3Test.class);
		suite.addTestSuite(FileTest.class);
		suite.addTestSuite(PwsFileFactoryTest.class);
		//$JUnit-END$
		return suite;
	}

}
