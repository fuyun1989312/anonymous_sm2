package anonymous_sm2;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import SM3_package.SM3Digest;

public class anonymous_sm2 {
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
	
	private static SecureRandom random = new SecureRandom();
	private ECCurve.Fp curve;
	private ECPoint G;
	
	//按照16进制的方式打印字符串
	public static void printHexString(byte[] b) {

		for (int i = 0; i < b.length; i++) {
			String hex = Integer.toHexString(b[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			System.out.print(hex.toUpperCase());

		}
		System.out.println();
	}
	
	//将byte数组转换为String
	public static String ByteToString(byte[] b)
	{
		String re=new String();
		for (int i = 0; i < b.length; i++) {
			String hex = Integer.toHexString(b[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}

			re+=hex.toUpperCase();

		}

		return re;
	}
	
	public static byte charToByte(char c)   
    {  
        return (byte) "0123456789ABCDEF".indexOf(c);  
    }  
	
	public static byte[] hexStringToBytes(String hexString)   
    {  
        if (hexString == null || hexString.equals(""))   
        {  
            return null;  
        }  
          
        hexString = hexString.toUpperCase();  
        int length = hexString.length() / 2;  
        char[] hexChars = hexString.toCharArray();  
        byte[] d = new byte[length];  
        for (int i = 0; i < length; i++)   
        {  
            int pos = i * 2;  
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));  
        }  
        return d;  
    }  
	
	
	//选取随机数，该随机数小于参数max
	public BigInteger random(BigInteger max) {

		BigInteger r = new BigInteger(256, random);
		// int count = 1;

		while (r.compareTo(max) >= 0) {
			r = new BigInteger(128, random);
			// count++;
		}

		// System.out.println("count: " + count);
		return r;
	}
		
	//判断大数param是否在min和max之间
	private boolean between(BigInteger param, BigInteger min, BigInteger max) {
		if (param.compareTo(min) >= 0 && param.compareTo(max) < 0) {
			return true;
		} else {
			return false;
		}
	}
	
	public String[] signature(byte[] input, BigInteger privateKey)
	{
		String[] sign=new String[3];
		SM3Digest sm3_str=new SM3Digest();
		sm3_str.update(input, 0, input.length);
		byte[] buf=new byte[32];
		sm3_str.doFinal(buf, 0);
		
		String str=ByteToString(buf);
		BigInteger e=new BigInteger(str,16);

		BigInteger k=random(n.subtract(new BigInteger("1")));
		
		ECPoint C1=G.multiply(k);
		BigInteger x=C1.getX().toBigInteger();
		BigInteger r=x.add(e).mod(n);
		
		if(0==r.compareTo(new BigInteger("0"))||0==n.compareTo(r.add(k)))
		{
			System.out.println("签名结果r错误！");
			sign[0] = "fasle".toString();
			return sign;
		}

		BigInteger I=new BigInteger("1",16);
		BigInteger tmp1=I.add(privateKey).modInverse(n);
		BigInteger tmp2=k.subtract(r.multiply(privateKey).mod(n)).mod(n);
		BigInteger s=tmp1.multiply(tmp2).mod(n);
		
		if(0==s.compareTo(new BigInteger("0")))
		{
			System.out.println("签名结果s为0！");
			sign[0] = "false".toString();
			return sign;
		}
		sign[0] = "true".toString();
		sign[1]=r.toString(16);
		sign[2]=s.toString(16);
		return sign;
	}
	
	public boolean verify(byte[] input,String[] sign, ECPoint publicKey)
	{
		if(sign[0].length()==1)
		{
			System.out.println("签名消息错误！");
			return false;
		}
		SM3Digest sm3_str=new SM3Digest();
		sm3_str.update(input, 0, input.length);
		byte[] buf=new byte[32];
		sm3_str.doFinal(buf, 0);
		
		String str=ByteToString(buf);
		BigInteger e=new BigInteger(str,16);

		BigInteger r=new BigInteger(sign[0],16);
		BigInteger s=new BigInteger(sign[1],16);
		
		if(!between(r,new BigInteger("1"),n.subtract(new BigInteger("1"))))
		{
			System.out.println("签名结果r错误！");
			return false;
		}

		
		if(!between(s,new BigInteger("1"),n.subtract(new BigInteger("1"))))
		{
			System.out.println("签名结果s错误！");
			return false;
		}
		
		BigInteger t=r.add(s).mod(n);
		
		if(0==t.compareTo(new BigInteger("0")))
		{
			System.out.println("验证结果t错误！");
			return false;
		}
		
		ECPoint C1=G.multiply(s);
		ECPoint C2=publicKey.multiply(t);
		ECPoint C3=C1.add(C2);
		BigInteger x=C3.getX().toBigInteger();
		BigInteger r_tmp=e.add(x).mod(n);
			
		r.compareTo(r_tmp);
		
		if(0==r.compareTo(r_tmp)){
			return true;
		}
		else{
			System.out.println("最终验证错误！");
			return false;
		}
	}
	
	public boolean supervise(String[] sign, int i, ECPoint[] onePublicKey, BigInteger a,
			ECPoint[] publicKey) {
		SM3Digest sm3 = new SM3Digest();
		ECPoint tmp = onePublicKey[0].multiply(a);
		BigInteger aR = new BigInteger(ByteToString(sm3.sm3_str(tmp.getEncoded())), 16);
		ECPoint tmp1 = publicKey[1].add(publicKey[i]).add(G.multiply(aR.mod(n)));
		String str1 = ByteToString(onePublicKey[1].getEncoded());
		String str2 = ByteToString(tmp1.getEncoded());
		if (0 == str1.compareTo(str2))
			return true;
		else
			return false;
	}
	
	public anonymous_sm2() {
		curve = new ECCurve.Fp(p, a, b); 
		G = curve.createPoint(gx, gy, false);
	}
	
	//使用用户公钥生成一次验签公钥，其中i表示随机选取的Mi
	public ECPoint[] one_publickey(int i, ECPoint[] publicKey) {
		ECPoint[] onePublicKey = new ECPoint[2];
		BigInteger r = random(n.subtract(new BigInteger("1")));
		ECPoint R = G.multiply(r);
		ECPoint tmp = publicKey[0].multiply(r);
		SM3Digest sm3 = new SM3Digest();
		BigInteger rA = new BigInteger(ByteToString(sm3.sm3_str(tmp.getEncoded())), 16);
		onePublicKey[1] = publicKey[1].add(publicKey[i]).add(G.multiply(rA.mod(n)));
		onePublicKey[0] = R;
		return onePublicKey;
	}
	//使用用户私钥生成一次签名私钥，其中i表示随机选取的mi
	public BigInteger one_privatekey(int i, ECPoint R, BigInteger[] privateKey) {
		ECPoint tmp = R.multiply(privateKey[0]);
		SM3Digest sm3 = new SM3Digest();
		BigInteger aR = new BigInteger(ByteToString(sm3.sm3_str(tmp.getEncoded())), 16);
		BigInteger x = aR.add(privateKey[1]).add(privateKey[i]).mod(n);
		return x;
	}
	
	public static void main(String[] args) {
		System.out.println("=====匿名认证算法测试=====");
		System.out.println("param n   :" + n.toString(16));
		System.out.println("param p   :" + p.toString(16));
		System.out.println("param a   :" + a.toString(16));
		System.out.println("param b   :" + b.toString(16));
		System.out.println("param gx  :" + gx.toString(16));
		System.out.println("param gy  :" + gy.toString(16));
		System.out.println("=====生成公私钥对（包括4对密钥参数，共6对）=====");

		
		anonymousKeyPair Asm2Key = new anonymousKeyPair();
		ECPoint[] Asm2publicKey = Asm2Key.get_publicKey();
		BigInteger[] Asm2privateKey = Asm2Key.get_privateKey();
		
		String tmp= ByteToString(Asm2publicKey[0].getEncoded());
		String tmp1=tmp.substring(2, (tmp.length()-2)/2+2);
		String tmp2=tmp.substring((tmp.length()-2)/2+2);
		System.out.println("pbulickey  A   :" + tmp1);
		System.out.println("               :" + tmp2);
		
		System.out.println("privatekey a   :" + Asm2privateKey[0].toString(16));
		tmp= ByteToString(Asm2publicKey[1].getEncoded());
		tmp1=tmp.substring(2, (tmp.length()-2)/2+2);
		tmp2=tmp.substring((tmp.length()-2)/2+2);
		System.out.println("pbulickey  B   :" + tmp1);
		System.out.println("               :" + tmp2);
		System.out.println("privatekey b   :" + Asm2privateKey[1].toString(16));
		tmp= ByteToString(Asm2publicKey[2].getEncoded());
		tmp1=tmp.substring(2, (tmp.length()-2)/2+2);
		tmp2=tmp.substring((tmp.length()-2)/2+2);
		System.out.println("pbulickey  M1  :" + tmp1);
		System.out.println("               :" + tmp2);
		System.out.println("privatekey m1  :" + Asm2privateKey[2].toString(16));
		tmp= ByteToString(Asm2publicKey[3].getEncoded());
		tmp1=tmp.substring(2, (tmp.length()-2)/2+2);
		tmp2=tmp.substring((tmp.length()-2)/2+2);
		System.out.println("pbulickey  M2  :" + tmp1);
		System.out.println("               :" + tmp2);
		System.out.println("privatekey m2  :" + Asm2privateKey[3].toString(16));
		tmp= ByteToString(Asm2publicKey[4].getEncoded());
		tmp1=tmp.substring(2, (tmp.length()-2)/2+2);
		tmp2=tmp.substring((tmp.length()-2)/2+2);
		System.out.println("pbulickey  M3  :" + tmp1);
		System.out.println("               :" + tmp2);
		System.out.println("privatekey m3  :" + Asm2privateKey[4].toString(16));
		tmp= ByteToString(Asm2publicKey[5].getEncoded());
		tmp1=tmp.substring(2, (tmp.length()-2)/2+2);
		tmp2=tmp.substring((tmp.length()-2)/2+2);
		System.out.println("pbulickey  M4  :" + tmp1);
		System.out.println("               :" + tmp2);
		System.out.println("privatekey m4  :" + Asm2privateKey[5].toString(16));
		System.out.println("其中的监管密钥为(a,B)");
		System.out.println("=====生成一次签名公私钥对(选取第2个密钥参数)=====");
		
		
		anonymous_sm2 Asm2 = new anonymous_sm2();
		ECPoint[] onePublicKey = Asm2.one_publickey(3, Asm2publicKey);// 此处从0开始算第一个，生成的公钥第一个是R，第二个是P
		BigInteger onePrivateKey = Asm2.one_privatekey(3, onePublicKey[0], Asm2privateKey);
		System.out.println("onePublicKey  i  :"+"2");
		tmp= ByteToString(onePublicKey[0].getEncoded());
		tmp1=tmp.substring(2, (tmp.length()-2)/2+2);
		tmp2=tmp.substring((tmp.length()-2)/2+2);
		System.out.println("onePublicKey  R  :" + tmp1);
		System.out.println("                 :" + tmp2);
		tmp= ByteToString(onePublicKey[1].getEncoded());
		tmp1=tmp.substring(2, (tmp.length()-2)/2+2);
		tmp2=tmp.substring((tmp.length()-2)/2+2);
		System.out.println("onePublicKey  P  :" + tmp1);
		System.out.println("                 :" + tmp2);
		System.out.println("onePrivateKey x  :"+onePrivateKey.toString(16));
		System.out.println("=====对认证交易信息进行签名=====");

		System.out.println("签名消息 msg :"+"abc");
		String[] sign_tmp=Asm2.signature("abc".getBytes(), onePrivateKey);
		String[] sign=new String[2];
		if(0==sign_tmp[0].compareTo("true"))
		{
			sign[0]=sign_tmp[1];
			sign[1]=sign_tmp[2];
			System.out.println("签名结果 r   :"+sign[0]);
			System.out.println("签名结果 s   :"+sign[1]);
		}
		
		System.out.println("=====对认证交易信息进行验签=====");
		
		
		
		if(Asm2.verify("abc".getBytes(), sign, onePublicKey[1]))
		{
			System.out.println("验证成功！");
		}
		
		System.out.println("=====对签名信息进行判定=====");
		if (Asm2.supervise(sign, 3, onePublicKey, Asm2privateKey[0], Asm2publicKey)) {
			System.out.println("检测成功！");
		}
		else{
			System.out.println("检测失败！");
		}
		long startTime=System.currentTimeMillis();
		for (int j = 0; j < 10; j++) {
			Asm2.supervise(sign, 3, onePublicKey, Asm2privateKey[0], Asm2publicKey);
		}
		long endTime=System.currentTimeMillis();
		System.out.println("程序运行时间："+(endTime-startTime)/10+"ms");
	}
}
