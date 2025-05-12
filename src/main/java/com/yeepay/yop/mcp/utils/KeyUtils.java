package com.yeepay.yop.mcp.utils;

import com.yeepay.yop.mcp.model.KeyType;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class KeyUtils {

    public static final SM2P256V1Curve CURVE = new SM2P256V1Curve();
    public final static BigInteger SM2_ECC_N = CURVE.getOrder();
    public final static BigInteger SM2_ECC_H = CURVE.getCofactor();
    public final static BigInteger SM2_ECC_GX = new BigInteger(
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    public final static BigInteger SM2_ECC_GY = new BigInteger(
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
    public static final ECPoint G_POINT = CURVE.createPoint(SM2_ECC_GX, SM2_ECC_GY);
    public static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(CURVE, G_POINT,
            SM2_ECC_N, SM2_ECC_H);
    private static final String ALGO_NAME_EC = "EC";

    static {
        if (Security.getProvider("BC") == null) {
            try {
                Security.addProvider(new BouncyCastleProvider());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static String generateSecretKey(KeyType keytype) throws Exception {
        try {
            return generateSymmetricKey(keytype);
        } catch (Exception e) {
            //throw new Exception("不支持的算法名称：" + keytype.getName());
            throw e;
        }
    }

    private static String generateSymmetricKey(KeyType keytype) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(keytype.getName());
        keyGenerator.init(keytype.getLength(), new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        return new String(Base64.encode(secretKey.getEncoded()));
    }

    public static String[] generateKey(KeyType keytype)
            throws Exception {
        KeyPairGenerator keyPairGenerator = null;
        try {
            SecureRandom secureRandom = new SecureRandom();
            if (KeyType.RSA2048 == keytype) {
                keyPairGenerator = KeyPairGenerator.getInstance(keytype.getName());
                keyPairGenerator.initialize(keytype.getLength(), secureRandom);
            }
            if (KeyType.SM2 == keytype) {
                keyPairGenerator = KeyPairGenerator.getInstance(ALGO_NAME_EC, BouncyCastleProvider.PROVIDER_NAME);
                ECGenParameterSpec parameterSpec = new ECGenParameterSpec("sm2p256v1");
                keyPairGenerator.initialize(parameterSpec, secureRandom);
            }
        } catch (NoSuchAlgorithmException e) {
            //throw new Exception("不支持的算法名称：" + keytype.getName());
            throw e;
        }
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String[] result = new String[2];
        result[0] = new String(Base64.encode(privateKey.getEncoded()));
        result[1] = new String(Base64.encode(publicKey.getEncoded()));
        return result;
    }

}
