/*
 * Copyright: Copyright (c)2011
 * Company: 易宝支付(YeePay)
 */
package com.yeepay.yop.mcp.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * title: <br/>
 * description: <br/>
 * Copyright: Copyright (c) 2018<br/>
 * Company: 易宝支付(YeePay)<br/>
 *
 * @author wenbo.fan-1
 * @version 1.0.0
 * @since 2021/2/3 2:09 上午
 */
public class Sm2Utils {


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
    public static final int CURVE_LEN = getCurveLength(DOMAIN_PARAMS);
    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");

    /**
     * 密钥对象转换成string
     *
     * @param key
     * @return
     */
    public static String key2String(Key key) {
        return StringUtils.newStringUtf8(Base64.encodeBase64(key.getEncoded()));
    }

    /**
     * sm2密钥进行签名
     *
     * @param data
     * @param priKey
     * @return URl安全的base64编码后的签名
     */
    public static String sign(String data, BCECPrivateKey priKey) {
        try {
            byte[] dataByte = data.getBytes();
            return Base64Utils.urlSafeEncode(sign(priKey, dataByte));
        } catch (CryptoException e) {
            e.printStackTrace();
            throw new RuntimeException("UnExpectedException occurred when sign content");
        }

    }

    /**
     * sm2密钥进行签名验证
     *
     * @param data
     * @param signature
     * @param publicKey
     * @return
     */
    public static boolean verifySign(String data, String signature, BCECPublicKey publicKey) {
        try {
            byte[] signByte = Base64Utils.decode(signature);
            byte[] dataByte = data.getBytes();
            return verify(publicKey, dataByte, encodeSM2SignToDER(signByte));
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * 把64字节的纯R+S字节数组编码成DER编码
     *
     * @param rawSign 64字节数组形式的SM2签名值，前32字节为R，后32字节为S
     * @return DER编码后的SM2签名值
     * @throws IOException
     */
    public static byte[] encodeSM2SignToDER(byte[] rawSign) throws IOException {
        //要保证大数是正数
        BigInteger r = new BigInteger(1, extractBytes(rawSign, 0, 32));
        BigInteger s = new BigInteger(1, extractBytes(rawSign, 32, 32));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    private static byte[] extractBytes(byte[] src, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(src, offset, result, 0, result.length);
        return result;
    }

    /**
     * 验签
     *
     * @param pubKey  公钥
     * @param srcData 原文
     * @param sign    DER编码的签名值
     * @return
     */
    public static boolean verify(BCECPublicKey pubKey, byte[] srcData, byte[] sign) {
        ECParameterSpec parameterSpec = pubKey.getParameters();
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(),
                parameterSpec.getN(), parameterSpec.getH());
        ECPublicKeyParameters pubKeyParameters = new ECPublicKeyParameters(pubKey.getQ(), domainParameters);
        return verify(pubKeyParameters, null, srcData, sign);
    }

    public static boolean verify(ECPublicKeyParameters pubKeyParameters, byte[] withId, byte[] srcData, byte[] sign) {
        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        if (withId != null) {
            param = new ParametersWithID(pubKeyParameters, withId);
        } else {
            param = pubKeyParameters;
        }
        signer.init(false, param);
        signer.update(srcData, 0, srcData.length);
        return signer.verifySignature(sign);
    }

    /**
     * string类型的公钥转换成公钥对象
     *
     * @param pubKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchProviderException
     */
    public static PublicKey string2PublicKey(String pubKey) {
        try {
            byte[] x509Bytes = Base64Utils.decode(pubKey);
            X509EncodedKeySpec eks = new X509EncodedKeySpec(x509Bytes);
            KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePublic(eks);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }

    }

    /**
     * string类型的私钥转换后私钥对象
     *
     * @param priKey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchProviderException
     */
    public static PrivateKey string2PrivateKey(String priKey) {
        try {
            byte[] pkcs8Key = Base64Utils.decode(priKey);
            PKCS8EncodedKeySpec peks = new PKCS8EncodedKeySpec(pkcs8Key);
            KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePrivate(peks);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }

    }

    /**
     * 签名
     *
     * @param priKey  私钥
     * @param srcData 原文
     * @return 64字节的纯R+S字节流
     * @throws CryptoException
     */
    public static byte[] sign(BCECPrivateKey priKey, byte[] srcData) throws CryptoException {
        ECParameterSpec parameterSpec = priKey.getParameters();
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(),
                parameterSpec.getN(), parameterSpec.getH());
        ECPrivateKeyParameters priKeyParameters = new ECPrivateKeyParameters(priKey.getD(), domainParameters);
        //der编码后的签名值
        byte[] derSign = sign(priKeyParameters, null, srcData);

        //der解码过程
        ASN1Sequence as = DERSequence.getInstance(derSign);
        byte[] rBytes = ((ASN1Integer) as.getObjectAt(0)).getValue().toByteArray();
        byte[] sBytes = ((ASN1Integer) as.getObjectAt(1)).getValue().toByteArray();
        //由于大数的补0规则，所以可能会出现33个字节的情况，要修正回32个字节
        rBytes = fixToCurveLengthBytes(rBytes);
        sBytes = fixToCurveLengthBytes(sBytes);
        byte[] rawSign = new byte[rBytes.length + sBytes.length];
        System.arraycopy(rBytes, 0, rawSign, 0, rBytes.length);
        System.arraycopy(sBytes, 0, rawSign, rBytes.length, sBytes.length);
        return rawSign;
    }

    /**
     * 签名
     *
     * @param priKeyParameters 私钥
     * @param withId           可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData          源数据
     * @return DER编码后的签名值
     * @throws CryptoException
     */
    public static byte[] sign(ECPrivateKeyParameters priKeyParameters, byte[] withId, byte[] srcData)
            throws CryptoException {
        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        ParametersWithRandom pwr = new ParametersWithRandom(priKeyParameters, new SecureRandom());
        if (withId != null) {
            param = new ParametersWithID(pwr, withId);
        } else {
            param = pwr;
        }
        signer.init(true, param);
        signer.update(srcData, 0, srcData.length);
        return signer.generateSignature();
    }

    /**
     * 通过私钥获取公钥
     *
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static PublicKey buildECPublicKeyByPrivateKey(BCECPrivateKey privateKey) throws Exception {
        ECParameterSpec parameterSpec = privateKey.getParameters();
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(),
                parameterSpec.getN(), parameterSpec.getH());
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(), domainParameters);
        ECPoint q = new FixedPointCombMultiplier().multiply(domainParameters.getG(), privateKeyParameters.getD());
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(q, domainParameters);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(q, parameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePublic(keySpec);
    }

    private static byte[] fixToCurveLengthBytes(byte[] src) {
        if (src.length == CURVE_LEN) {
            return src;
        }

        byte[] result = new byte[CURVE_LEN];
        if (src.length > CURVE_LEN) {
            System.arraycopy(src, src.length - result.length, result, 0, result.length);
        } else {
            System.arraycopy(src, 0, result, result.length - src.length, src.length);
        }
        return result;
    }

    public static int getCurveLength(ECDomainParameters domainParams) {
        return (domainParams.getCurve().getFieldSize() + 7) / 8;
    }


}
