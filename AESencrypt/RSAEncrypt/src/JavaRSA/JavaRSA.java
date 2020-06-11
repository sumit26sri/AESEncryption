package JavaRSA ;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class JavaRSA extends Applet
{
	final static byte[] Hash = new byte[32];
	final static byte[] Sign = new byte[256];
	short hash_len = 0;
	short Sign_len = 0;
	
	public static final byte INS_GEN_KEYPAIR = (short)0x10;
	public static final byte INS_GET_PUBKEY = (short)0x20;
	public static final byte INS_ENCRYPT = (short)0x30;
	public static final byte INS_DECRYPT = (short)0x40;
	
	MessageDigest mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
	Cipher rsaCCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1_OAEP, false);
	KeyPair rsaKey = new KeyPair(KeyPair.ALG_RSA,KeyBuilder.LENGTH_RSA_2048);
	RSAPublicKey rsaPubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_2048,false);
	 


	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new JavaRSA().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();

		
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_GEN_KEYPAIR:
			rsaKey.genKeyPair();
			break;
			
	    case INS_GET_PUBKEY:
	    	rsaPubKey = (RSAPublicKey)rsaKey.getPublic();
	    	rsaPubKey.getModulus(buf,(short)0x00);
	    	apdu.setOutgoingAndSend((short)0x00,(short)256);
	    	break;
	    	
	    case INS_ENCRYPT:
	    	mDigest.reset();
	    	hash_len = mDigest.doFinal(buf,(short)ISO7816.OFFSET_CDATA,len,Hash,(short)0x00);
	    	rsaCCipher.init(rsaKey.getPrivate(), Cipher.MODE_ENCRYPT);
	    	Sign_len= rsaCCipher.doFinal(Hash,(short)0x00,hash_len,Sign,(short)0x00);
	    	Util.arrayCopy(Hash,(short)0x00, buf,(short)0x00,hash_len);
	    	apdu.setOutgoingAndSend((short)0x00, hash_len);
	    	break;
	    	
	    case INS_DECRYPT:
	    	mDigest.reset();
	    	hash_len = mDigest.doFinal(buf,(short) ISO7816.OFFSET_EXT_CDATA,len, Hash,(short)0x00);
	    	rsaCCipher.init(rsaKey.getPrivate(),Cipher.MODE_DECRYPT);
	    	Sign_len = rsaCCipher.doFinal(Hash,(short)0x00,hash_len,Sign,(short)0x00);
	    	Util.arrayCopy(Hash,(short)0x00,buf,(short)0x00,hash_len);
	    	apdu.setOutgoingAndSend((short)0x00,hash_len);
	    	break ;
	    	
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

}
