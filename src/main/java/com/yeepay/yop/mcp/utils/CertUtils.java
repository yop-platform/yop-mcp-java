/*
 * Copyright: Copyright (c)2011
 * Company: 易宝支付(YeePay)
 */
package com.yeepay.yop.mcp.utils;

import com.yeepay.yop.mcp.config.Config;
import com.yeepay.yop.mcp.model.KeyType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static com.yeepay.yop.mcp.utils.ConfigUtils.YOP_TEST_CONFIG_FILE;

/**
 * title: <br/>
 * description: <br/>
 * Copyright: Copyright (c) 2018<br/>
 * Company: 易宝支付(YeePay)<br/>
 *
 * @author wenbo.fan-1
 * @version 1.0.0
 * @since 2021/4/6 2:36 下午
 */
public class CertUtils {

    /**
     * 生成p10请求文件
     *
     * @param priKey
     * @param pubKey
     * @param keyType
     * @return
     */
    public static String genP10(String priKey, String pubKey, KeyType keyType) {
        PublicKey publicKey = string2PublicKey(pubKey, keyType);
        PrivateKey privateKey = string2PrivateKey(priKey, keyType);
        try {
            X500Principal x500Principal = new X500Principal("");
            Signature signature = Signature.getInstance(getSignatureAlg(keyType), "BC");
            signature.initSign(privateKey);
            signature.sign();
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                    x500Principal, publicKey);
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(getSignatureAlg(keyType));
            ContentSigner signer = csBuilder.build(privateKey);
            return Base64Utils.encode(p10Builder.build(signer).getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * 合成cer后缀的公钥证书
     */
    public static void makePubCert(String pemCert, String serialNo, String certPath) {
        try {
            String pubCertPath = certPath + serialNo + ".cer";
            if (!SupportUtils.isFileExists(pubCertPath)) {
                if (!SupportUtils.isFileExists(certPath)) {
                    SupportUtils.mkDir(certPath);
                }

                FileOutputStream certOut = new FileOutputStream(certPath + serialNo + ".cer");
                certOut.write(pemCert.getBytes());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 合成pfx证书
     *
     * @param priKey
     * @param pemCert
     * @param keyType
     * @param pwd
     * @param serialNo
     */
    public static void makePfxCert(String priKey, String pemCert, KeyType keyType, String pwd, String serialNo, String certPath) {
        PrivateKey privateKey = string2PrivateKey(priKey, keyType);
        byte[] certBytes = pemCert.getBytes();
        try {
            if (!SupportUtils.isFileExists(certPath)) {
                SupportUtils.mkDir(certPath);
            }
            String priCertPath = certPath + serialNo + ".pfx";
            if (!SupportUtils.isFileExists(priCertPath)) {
                X509Certificate certificate = getX509Certificate(certBytes);
                String alias = "{" + serialNo + "}";
                char[] pwdChars = pwd.toCharArray();
                X509Certificate[] cfcaCertificate = loadCertChain(keyType);
                KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
                keystore.load(null, pwdChars);
                keystore.setKeyEntry(alias, privateKey, pwdChars, new Certificate[]{certificate, cfcaCertificate[1], cfcaCertificate[0]});
                keystore.store(new FileOutputStream(certPath + serialNo + ".pfx"), pwdChars);
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    private static String getSignatureAlg(KeyType keyType) {
        if (KeyType.RSA2048.equals(keyType)) {
            return "SHA256withRSA";
        } else if (KeyType.SM2.equals(keyType)) {
            return "SM3withSM2";
        } else {
            throw new RuntimeException("unsupported alg");
        }
    }

    public static X509Certificate getX509Certificate(byte[] certBytes) throws CertificateException,
            NoSuchProviderException {
        ByteArrayInputStream bais = new ByteArrayInputStream(certBytes);
        return getX509Certificate(bais);
    }

    public static X509Certificate getX509Certificate(InputStream is) throws CertificateException,
            NoSuchProviderException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return (X509Certificate) cf.generateCertificate(is);
    }

    public static PublicKey string2PublicKey(String pubKey, KeyType keyType) {
        try {
            return KeyFactory.getInstance(keyType.getAlg(), BouncyCastleProvider.PROVIDER_NAME).generatePublic(new X509EncodedKeySpec(Base64Utils.decode(pubKey)));
        } catch (Exception e) {
            throw new RuntimeException("No such algorithm.", e);
        }

    }

    public static PrivateKey string2PrivateKey(String priKey, KeyType keyType) {
        try {
            return KeyFactory.getInstance(keyType.getAlg()).generatePrivate(new PKCS8EncodedKeySpec(Base64Utils.decode(priKey)));
        } catch (Exception e) {
            throw new RuntimeException("No such algorithm.", e);
        }
    }

    public static X509Certificate[] loadCertChain(KeyType keyType) throws Exception {
        String rootCertName;
        String middleCertName;
        String qaHostPath = Config.QA_HOST_PATH + YOP_TEST_CONFIG_FILE;
        if (!SupportUtils.isFileExists(qaHostPath)) {
            if (KeyType.SM2.equals(keyType)) {
                rootCertName = "CFCA_SM2_ACS_CA.pem";
                middleCertName = "CFCA_SM2_ACS_OCA31.pem";
            } else if (KeyType.RSA2048.equals(keyType)) {
                rootCertName = "CFCA_RSA_ACS_CA.pem";
                middleCertName = "CFCA_RSA_ACS_OCA31.pem";
            } else {
                throw new Exception("unsupported alg");
            }
        } else {
            if (KeyType.SM2.equals(keyType)) {
                rootCertName = "CFCA_SM2_ACS_TEST_SM2_CA.cer";
                middleCertName = "CFCA_SM2_ACS_TEST_SM2_OCA31.cer";
            } else if (KeyType.RSA2048.equals(keyType)) {
                rootCertName = "CFCA_RSA_ACS_TEST_CA.cer";
                middleCertName = "CFCA_RSA_ACS_TEST_OCA31.cer";
            } else {
                throw new Exception("unsupported alg");
            }
        }

        X509Certificate[] certificates = new X509Certificate[3];
        InputStream rootCertStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(rootCertName);
        byte[] rootCertBytes = read(rootCertStream);
        certificates[0] = getX509Certificate(rootCertBytes);
        InputStream certStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(middleCertName);
        byte[] certBytes = read(certStream);
        certificates[1] = getX509Certificate(certBytes);
        return certificates;
    }

    public static byte[] read(InputStream inputStream) throws IOException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int num = inputStream.read(buffer);
            while (num != -1) {
                baos.write(buffer, 0, num);
                num = inputStream.read(buffer);
            }
            baos.flush();
            return baos.toByteArray();
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
        }
    }
}
