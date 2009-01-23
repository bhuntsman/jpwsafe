package org.pwsafe.lib.file;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import com.amazonaws.s3.S3;
import com.amazonaws.s3.S3Object;
import com.sun.org.apache.xml.internal.security.utils.Base64;

public class PwsS3Storage implements PwsStorage {
	public static class Credentials {
		String keyId;
		String secretKey;
		public Credentials(String id, String secret) {
			keyId = id;
			secretKey = secret;
		}
	}
	private S3 s3;
	private String bucket;
	private String filename;
	private InputStream dbstream;
	public PwsS3Storage(String bucket, String filename, Credentials credentials) {
		System.out.println("bucket = "+bucket);
		System.out.println("filename = "+filename);
		System.out.println("id = "+credentials.keyId);
		System.out.println("secret = "+credentials.secretKey);
		this.bucket = bucket;
		this.filename = filename;
		s3 = new S3( S3.HTTPS_URL, credentials.keyId, credentials.secretKey );
	}
	public PwsStorage clone(String prefix) {
		// TODO Auto-generated method stub
		return null;
	}

	public void close() throws IOException {
		// Nothing to do, not persistent connection
	}

	public InputStream getInputStream() throws IOException {
		if (dbstream!=null) return dbstream;
		try {
			S3Object obj = s3.getObject(bucket, filename);
			String data = obj.getData();
			byte[] bytes = Base64.decode(data.getBytes());
			dbstream = new ByteArrayInputStream(bytes); 
			return dbstream;
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return null;
		}
		// TODO Auto-generated method stub
	}

	public boolean save(byte[] bytes) throws IOException {
		String data = Base64.encode(bytes);
		try {
			s3.putObjectInline(bucket, filename, data);
			return true;
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return false;			
		}
	}
	
	public static PwsS3Storage fromFile(String filename) throws IOException {
		FileInputStream fin = new FileInputStream(filename);
		InputStreamReader isr = new InputStreamReader(fin);
		BufferedReader br = new BufferedReader(isr);
		String bucket = br.readLine();
		String id = br.readLine();
		String secret = br.readLine();
		Credentials credentials = new Credentials(id, secret);
		PwsS3Storage pss = new PwsS3Storage(bucket, "pwsafe_data", credentials);
		return pss;
	}
	
//	public S3Test( String URL, String AWS_KEY_ID, String SECRET_KEY ) {
//        try {
//            System.out.println( "----------------------------------------------------------------------------------" );                        
//            System.out.println( "Start S3 Tests" );
//            System.out.println( "----------------------------------------------------------------------------------" );                        
//
//
//            String bucketName = AWS_KEY_ID + "-S3-TestBucket";
//            String key = AWS_KEY_ID + "-S3-TestKey";
//            String name = AWS_KEY_ID + " - S3 - Test Data";
//
//
//            S3 s3 = new S3( URL, AWS_KEY_ID, SECRET_KEY );
//            
//			
//            System.out.println( "List All Buckets" );
//			S3BucketList buckets = s3.listMyBuckets();                       
//			for ( int i = 0; i < buckets.getBuckets().size(); i++ ) {
//				System.out.println( "\t" + (String)buckets.getBuckets().elementAt( i ) );
//			}
//            
//			
//            System.out.println( "Create Bucket" );
//            s3.createBucket( bucketName );
//            
//			
//            System.out.println( "List All Buckets" );
//			buckets = s3.listMyBuckets();                       
//			for ( int i = 0; i < buckets.getBuckets().size(); i++ ) {
//				System.out.println( "\t" + (String)buckets.getBuckets().elementAt( i ) );
//			}
//
//
//            System.out.println( "Put Object Inline 1" );
//            s3.putObjectInline( bucketName, key, name );
//            
//			
//            System.out.println( "Put Object Inline 2" );
//            s3.putObjectInline( bucketName, key + "2", name + "2" );
//            
//			
//            System.out.println( "List Bucket" );
//			S3Bucket bucket = s3.listBucket( bucketName );
//			System.out.println( "\t Bucket Name : " + bucket.getBucketName() );
//			System.out.println( "\t Keys" + bucket.getBucketName() );
//			for ( int i = 0; i < bucket.getNames().size(); i++ ) {
//				System.out.println( "\t\t" + (String)bucket.getNames().elementAt( i ) );
//			}
//			     
//				        
//            System.out.println( "Get Object" );
//			S3Object object = s3.getObject( bucketName, key );
//			System.out.println( "\t Key  : " + object.getKey() );
//			System.out.println( "\t Data : " + object.getData() ); 
//            
//			
//            System.out.println( "List Bucket" );
//			bucket = s3.listBucket( bucketName );
//			System.out.println( "\t Bucket Name : " + bucket.getBucketName() );
//			System.out.println( "\t Keys" + bucket.getBucketName() );
//			for ( int i = 0; i < bucket.getNames().size(); i++ ) {
//				System.out.println( "\t\t" + (String)bucket.getNames().elementAt( i ) );
//			}
//            
//			
//            System.out.println( "Delete Object 1" );
//            s3.deleteObject( bucketName, key );
//            System.out.println( "Delete Object 2" );
//            s3.deleteObject( bucketName, key + "2" );
//            
//			
//            System.out.println( "Delete Bucket" );
//            s3.deleteBucket( bucketName );
//            
//			
//            System.out.println( "List All Buckets" );
//			buckets = s3.listMyBuckets();                       
//			for ( int i = 0; i < buckets.getBuckets().size(); i++ ) {
//				System.out.println( "\t" + (String)buckets.getBuckets().elementAt( i ) );
//			}
//
//
//            System.out.println( "----------------------------------------------------------------------------------" );                        
//            System.out.println( "End S3 Tests" );
//            System.out.println( "----------------------------------------------------------------------------------" );                        
//        }
//        catch ( Exception exception ) {
//            exception.printStackTrace();
//        }
//	}
}
