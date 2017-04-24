package anonymous_sm2;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

//生成一对SM2公私钥，而匿名算法中需要多对SM2KeyPair
public class SM2KeyPair {
	private ECPoint publicKey;
	private BigInteger privateKey;

	private static BigInteger n = new BigInteger("FFFFFFFE" + "FFFFFFFF"
			+ "FFFFFFFF" + "FFFFFFFF" + "7203DF6B" + "21C6052B" + "53BBF409"
			+ "39D54123", 16);
	private static BigInteger p = new BigInteger("FFFFFFFE" + "FFFFFFFF"
			+ "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF"
			+ "FFFFFFFF", 16);
	private static BigInteger a = new BigInteger("FFFFFFFE" + "FFFFFFFF"
			+ "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF"
			+ "FFFFFFFC", 16);
	private static BigInteger b = new BigInteger("28E9FA9E" + "9D9F5E34"
			+ "4D5A9E4B" + "CF6509A7" + "F39789F5" + "15AB8F92" + "DDBCBD41"
			+ "4D940E93", 16);
	private static BigInteger gx = new BigInteger("32C4AE2C" + "1F198119"
			+ "5F990446" + "6A39C994" + "8FE30BBF" + "F2660BE1" + "715A4589"
			+ "334C74C7", 16);
	private static BigInteger gy = new BigInteger("BC3736A2" + "F4F6779C"
			+ "59BDCEE3" + "6B692153" + "D0A9877C" + "C62A4740" + "02DF32E5"
			+ "2139F0A0", 16);
	
	private ECCurve.Fp curve;
	private ECPoint G;
	
	public SM2KeyPair() {
		curve = new ECCurve.Fp(p, // q
				a, // a
				b); // b

		G = curve.createPoint(gx, gy, false);
		anonymous_sm2 sm02 = new anonymous_sm2();
		
		
		this.privateKey = sm02.random(n.subtract(new BigInteger("1")));
		
		this.publicKey = G.multiply(this.privateKey);
		if (checkPublicKey(this.publicKey)) {
			//System.out.println("generate key successfully");

		} else {
			System.err.println("generate key failed");
		}
	}
	
	public ECPoint getPublicKey() {
		return publicKey;
	}

	public BigInteger getPrivateKey() {
		return privateKey;
	}
	
	private boolean between(BigInteger param, BigInteger min, BigInteger max) {
		if (param.compareTo(min) >= 0 && param.compareTo(max) < 0) {
			return true;
		} else {
			return false;
		}
	}
	
	public boolean checkPublicKey(ECPoint publicKey) {

		if (!publicKey.isInfinity()) {

			// BigInteger x = publicKey.getXCoord().toBigInteger();
			// BigInteger y = publicKey.getYCoord().toBigInteger();
			BigInteger x = publicKey.getX().toBigInteger();
			BigInteger y = publicKey.getY().toBigInteger();

			if (between(x, new BigInteger("0"), p)
					&& between(y, new BigInteger("0"), p)) {

				BigInteger xResult = x.pow(3).add(a.multiply(x)).add(b).mod(p);

				//System.out.println("xResult: " + xResult.toString());

				BigInteger yResult = y.pow(2).mod(p);

				//System.out.println("yResult: " + yResult.toString());

				if (yResult.equals(xResult)
						&& publicKey.multiply(n).isInfinity()) {
					return true;
				}
			}
			return false;
		} else {
			return false;
		}
	}
}
