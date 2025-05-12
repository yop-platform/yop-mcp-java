package com.yeepay.yop.mcp.utils;

import com.yeepay.yop.mcp.config.Config;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;


public class RSA {

    public static String sign(String content, String privateKey, String sign_rsaAlgorithm, String input_charset) {
        try {
            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64Utils.decode(privateKey));
            KeyFactory keyf = KeyFactory.getInstance("RSA");
            PrivateKey priKey = keyf.generatePrivate(priPKCS8);
            Signature signature = Signature.getInstance(sign_rsaAlgorithm);
            signature.initSign(priKey);
            signature.update(content.getBytes(input_charset));
            byte[] signed = signature.sign();
            return Base64Utils.urlSafeEncode(signed);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static boolean verify(String content, String sign, String ali_public_key, String sign_rsaAlgorithm, String input_charset) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = Base64Utils.decode(ali_public_key);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
            Signature signature = Signature.getInstance(sign_rsaAlgorithm);
            signature.initVerify(pubKey);
            signature.update(content.getBytes(input_charset));
            return signature.verify(Base64Utils.decode(sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static String convert2KeyFile(String key, String keyLength) {
        String fileName = Config.RSA_KEY_SAVE_PATH;
        if (!SupportUtils.isFileExists(fileName)) {
            SupportUtils.mkDir(fileName);
        }
        fileName = fileName + "应用私钥";
        if (!StringUtils.isEmpty(fileName)) {
            fileName = fileName + keyLength + ".txt";
            String file = new File(fileName).getAbsolutePath();
            try {
                SupportUtils.writeFileString(file, key);
            } catch (IOException e) {
                e.printStackTrace();
            }
            return file;
        }
        return "";
    }

    public static String mkRsaPublicKeyFile(String privateKeyFile, String keyLength)
            throws Exception {
        if (!new File(privateKeyFile).exists()) {
            return null;
        }
        String dir = Config.RSA_KEY_SAVE_PATH;
        String pubKey = buildPublicKeyByPrivateKey(SupportUtils.readFileAsString(privateKeyFile));
        FileOutputStream certOut = new FileOutputStream(dir + "应用公钥" + keyLength + ".txt");
        certOut.write(pubKey.getBytes());
        return new File(dir + "应用公钥" + keyLength + ".txt").getAbsolutePath();
    }

    public static String buildPublicKeyByPrivateKey(String priKey) throws Exception {
        PrivateKey privateKey = RSA.string2PrivateKey(priKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec priv = kf.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(priv.getModulus(), BigInteger.valueOf(65537));
        PublicKey publicKey = kf.generatePublic(keySpec);
        return RSA.key2String(publicKey);
    }

    public static String pkcs1ToPkcs8(String pkcs1Key) throws IOException {
        byte[] encodeByte = Base64Utils.decode(pkcs1Key);
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag);
        ASN1Object asn1Object = ASN1ObjectIdentifier.fromByteArray(encodeByte);
        PrivateKeyInfo privKeyInfo = new PrivateKeyInfo(algorithmIdentifier, asn1Object);
        byte[] pkcs8Bytes = fixPkcs8Bytes(privKeyInfo.getEncoded());
        return Base64Utils.encode(pkcs8Bytes);
    }

    private static byte[] fixPkcs8Bytes(byte[] pkcs8Bytes) {
        pkcs8Bytes[10] = 9;
        pkcs8Bytes[18] = 1;
        pkcs8Bytes[19] = 1;
        pkcs8Bytes[20] = 5;
        pkcs8Bytes[21] = 0;
        return pkcs8Bytes;
    }

    public static String pkcs8ToPkcs1(String pksc8Key) throws IOException {
        byte[] privBytes = Base64Utils.decode(pksc8Key);
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privBytes);
        ASN1Encodable encodable = pkInfo.parsePrivateKey();
        ASN1Primitive asn1Primitive = encodable.toASN1Primitive();
        byte[] privateKeyPKCS1 = asn1Primitive.getEncoded();
        return Base64Utils.encode(privateKeyPKCS1);
    }


    public static PrivateKey string2PrivateKey(String priKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64Utils.decode(priKey)));
    }

    public static String key2String(Key key) {
        return Base64Utils.encode(key.getEncoded());
    }

}
