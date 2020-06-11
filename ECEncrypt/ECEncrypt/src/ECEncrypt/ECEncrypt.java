package ECEncrypt ;

import javacard.framework.*;
import javacard.security.*;

public class ECEncrypt extends Applet
{
	
	byte[] baTemp = new byte[255];
    byte[] baPrivKeyU, baPrivKeyV, baPubKeyU, baPubKeyV;
    short len;

    KeyPair kpU, kpV;                    //class
    ECPrivateKey privKeyU, privKeyV;    //Interface
    ECPublicKey pubKeyU, pubKeyV;      //Interface
    KeyAgreement ecdhU, ecdhV;        //class
    
    //INSTRUCTION_BYTE_CODE
    public static final byte INS_PROC_INSD1 = (byte) 0xD1;
    public static final byte INS_PROC_INSD2 = (byte) 0xD2;
    public static final byte INS_PROC_INSD3 = (byte) 0xD3;
    
    protected ECEncrypt()
    {
	    register();
    } 
     private void processINSD1(APDU apdu){
	     //ProcessINSD1
	     try
	     {
	     	 kpU = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_128);
	     	 kpU.genKeyPair();
	         privKeyU = (ECPrivateKey)kpU.getPrivate();
	         pubKeyU = (ECPublicKey)kpU.getPublic();
	     
	         kpV = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_128);
	         kpV.genKeyPair();
	         privKeyV = (ECPrivateKey)kpV.getPrivate();
	         pubKeyV = (ECPublicKey)kpV.getPublic();
	     }
	      catch(Exception exception)
	      {
		      ISOException.throwIt((short) 0xFFD1);
	      }	     
     }
      private void processINSD2(APDU apdu){
	     //ProcessINSD2
	     byte[] buf = apdu.getBuffer();
	      try 
	      {
		    switch(buf[3])  
		    {
			case 0x01:      //PARAMETER_A
				if(buf[2] == 0x01)
				{
				 len = pubKeyU.getA(baTemp, (short)0x00);
				}
				else
				{
					len = pubKeyV.getA(baTemp,(short)0x00);
				}
				apdu.setOutgoing();
				apdu.setOutgoingLength((short)len);
				apdu.sendBytesLong(baTemp,(short)0x00, len);
				break;
			
			case 0x02:  //PARAMETER_B
			    if(buf[2]==0x01)
			    {
				   len = pubKeyU.getB(baTemp, (short)0);
			    }
			    else
			    {
				   len = pubKeyV.getB(baTemp, (short)0);
			    }
			    apdu.setOutgoing();
			    apdu.setOutgoingLength((short)len);
			    apdu.sendBytesLong(baTemp,(short)0, len);
			    break;
			
			case 0x03:  //  PARAMETER_P
				if(buf[2]==0x01)
				{
					len = pubKeyU.getField(baTemp, (short)0);
				}
				else
				{
					len= pubKeyV.getField(baTemp, (short)0);
				}
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) len);
				apdu.sendBytesLong(baTemp,(short)0x00, len);
				break;
			
			case 0x04:  //PUBLIC_KEY
				if(buf[2]==0x01)
				{
					len = pubKeyU.getW(baTemp,(short)0);
				}
				else
				{
					len = pubKeyV.getW(baTemp,(short)0);
				}
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) len);
				apdu.sendBytesLong(baTemp,(short)0,len);
				break;
			
			case 0x05:  //PRIVATE_KEY
				if(buf[2] == 0x01)
				{
					len = privKeyU.getS(baTemp, (short) 0);
				}
				else
				{
					len = privKeyV.getS(baTemp,(short) 0);
				}
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) len);
				apdu.sendBytesLong(baTemp,(short) 0, len);
				break;
			
			default:
				throw new IndexOutOfBoundsException();				
		    }		    
	      }
	      catch(CryptoException c)
	      {
	      	short reason =c.getReason();
	      	ISOException.throwIt(reason) ; 
	      }
	      
	     
     }
      private void processINSD3(APDU apdu){
	     //ProcessINSD3
	     byte[] buf = apdu.getBuffer();
	     
	     try
	     {
	     	switch (buf[2])
	     	{
			case 0x01: //Process "U" stand Point
				len = privKeyU.getS(baTemp, (short) 0);
				baPrivKeyU = new byte[len];
				Util.arrayCopyNonAtomic( baTemp,(short) 0, baPrivKeyU, (short) 0, len);
				
				
				len = pubKeyV.getW(baTemp,(short) 0);
				baPubKeyV = new byte[len];
				Util.arrayCopyNonAtomic(baTemp, (short) 0, baPubKeyV, (short) 0 , len);
				
				
				ecdhU = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
				ecdhU.init(privKeyU);
				len = ecdhU.generateSecret(baPubKeyV,(short) 0, len, baTemp,(short) 0);
				
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) len);
				apdu.sendBytesLong(baTemp, (short) 0, len);
				break;
				
			case 0x02: //Process "V" stand Point
				len = privKeyV.getS(baTemp, (short) 0);
				baPrivKeyV = new byte[len];
				Util.arrayCopyNonAtomic( baTemp,(short) 0, baPrivKeyV, (short) 0, len);
				
				len = pubKeyU.getW(baTemp, (short) 0);
				baPubKeyU = new byte[len];
				Util.arrayCopyNonAtomic(baTemp, (short) 0, baPubKeyU, (short) 0, len);
				
				ecdhV = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
				ecdhV.init(privKeyV);
				len = ecdhV.generateSecret(baPubKeyU, (short) 0, len, baTemp, (short) 0);
				
				
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) len);
				apdu.sendBytesLong(baTemp, (short) 0, len);
				break;
				
			default:
				throw new IndexOutOfBoundsException();
			
	     	}
		     
	     }
	     catch(Exception exception)
	     	{
		     	ISOException.throwIt((short) 0xFFD2);
	     	}
     }
    

	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new ECEncrypt();
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		
		if(buf[ISO7816.OFFSET_CLA] != 0x00)
		{
		ISOException.throwIt ((short)0x6660);	
		}
		switch (buf[ISO7816.OFFSET_INS])
		{
		case (byte)INS_PROC_INSD1:
			processINSD1(apdu);
			break;
		case (byte) INS_PROC_INSD2:
			processINSD2(apdu);
			break;
		case (byte)INS_PROC_INSD3:
			processINSD3(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

}