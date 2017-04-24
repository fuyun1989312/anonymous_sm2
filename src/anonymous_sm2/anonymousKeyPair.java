package anonymous_sm2;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

public class anonymousKeyPair {
	private BigInteger[] privateKey=new BigInteger[6];
	private ECPoint[] publicKey=new ECPoint[6];
	public anonymousKeyPair(){

		for(int i=0;i<6;i++){
			SM2KeyPair sm2Key=new SM2KeyPair();
			this.privateKey[i]=sm2Key.getPrivateKey();
			this.publicKey[i]=sm2Key.getPublicKey();
		}
	}
	public ECPoint[] get_publicKey(){
		return this.publicKey;
	}
	public BigInteger[] get_privateKey(){
		return this.privateKey;
	}
}
