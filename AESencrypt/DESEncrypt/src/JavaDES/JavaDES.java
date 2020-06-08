package JavaDES ;

import javacard.framework.*;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;


public class JavaDES extends Applet
{
	Cipher desCipher;
	DESKey desKey;
	APDU apdu;
	
	//Two different types of memory for different usage. each one has 16 (= 0x10) byte capacity.
     private byte[] volatileMem;
     private byte[] nonVolatileMem;
     
     private static final byte INS_SET_KEY = (byte)0x10;
     private static final byte INS_ENCRYPT = (byte)0x20;
     private static final byte INS_DECRYPT = (byte)0x30;
     
     


	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new JavaDES();
	}

    protected JavaDES(){
    	
    	volatileMem = JCSystem.makeTransientByteArray((short)0x10,JCSystem.CLEAR_ON_DESELECT);
    	nonVolatileMem = new byte[(short)0x10];
    	desCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
	    desKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES,false);
	    register();
    }
 
	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		
		
		if(buf[ISO7816.OFFSET_LC]!=(short)0x10)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);	
		}
		
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_SET_KEY:
			desKey.setKey(buf,ISO7816.OFFSET_CDATA);
			break;
		case INS_ENCRYPT:
			desCipher.init(desKey,Cipher.MODE_ENCRYPT);
			desCipher.doFinal(buf,(short)ISO7816.OFFSET_CDATA, (short)0x10,volatileMem,(short)0x00);
			Util.arrayCopyNonAtomic(volatileMem, (short)0x00, buf, (short)0x00,(short)0x10);
			apdu.setOutgoingAndSend((short)0x00,(short)0x10);
			break ;
		case INS_DECRYPT:
			desCipher.init(desKey,Cipher.MODE_DECRYPT);
			desCipher.doFinal(buf,(short)ISO7816.OFFSET_CDATA, (short)0x10, volatileMem, (short)0x00);
			Util.arrayCopyNonAtomic(volatileMem,(short)0x00,buf,(short)0x00,(short)0x10);
			apdu.setOutgoingAndSend((short)0x00,(short)0x10);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

}
