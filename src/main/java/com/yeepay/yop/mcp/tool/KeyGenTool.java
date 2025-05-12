/*
 * Copyright: Copyright (c)2011
 * Company: 易宝支付(YeePay)
 */
package com.yeepay.yop.mcp.tool;

import com.yeepay.yop.mcp.model.KeyGenRequest;
import com.yeepay.yop.mcp.model.KeyGenResponse;
import com.yeepay.yop.mcp.model.KeyType;
import com.yeepay.yop.mcp.utils.Base64Utils;
import com.yeepay.yop.mcp.utils.CertUtils;
import com.yeepay.yop.mcp.utils.KeyUtils;
import com.yeepay.yop.mcp.utils.SupportUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;

/**
 * title: <br>
 * description: 描述<br>
 * Copyright: Copyright (c)2014<br>
 * Company: 易宝支付(YeePay)<br>
 *
 * @author wenbo.fan-1
 * @version 1.0.0
 * @since 2025/5/9 10:56
 */
@Service
public class KeyGenTool {

    @Tool(description = "根据密钥算法生成非对称加密的密钥对（公钥和私钥），并保存到本地路径，支持RSA和SM2算法。如果代码语言是Java、Python、NodeJS、PHP、C#，则密钥格式为PKCS8；否则，密钥格式为PKCS1")
    public KeyGenResponse genKeypair(KeyGenRequest request) {
        KeyGenResponse response = new KeyGenResponse();
        try {
            // 解析密钥类型
            KeyType keyType;
            if ("RSA".equalsIgnoreCase(request.getAlgorithm())) {
                keyType = KeyType.RSA2048;
            } else if ("SM2".equalsIgnoreCase(request.getAlgorithm())) {
                keyType = KeyType.SM2;
            } else {
                throw new IllegalArgumentException("不支持的密钥算法: " + request.getAlgorithm());
            }

            // 生成密钥对
            String[] result = KeyUtils.generateKey(keyType);
            if (result.length != 2) {
                response.setMessage("生成密钥失败");
                return response;
            }

            // 如果是 PKCS#1 格式，则转换私钥编码方式
            if (!"PKCS8".equalsIgnoreCase(request.getFormat())) {
                if (KeyType.SM2.equals(keyType)) {
                    throw new IllegalArgumentException("SM2密钥只支持生成PKCS8格式");
                }
                PrivateKey priv = CertUtils.string2PrivateKey(result[0], KeyType.RSA2048);
                byte[] privBytes = priv.getEncoded();
                PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privBytes);
                ASN1Encodable encodable = pkInfo.parsePrivateKey();
                ASN1Primitive asn1Primitive = encodable.toASN1Primitive();
                byte[] privateKeyPKCS1 = asn1Primitive.getEncoded();
                result[0] = Base64Utils.encode(privateKeyPKCS1);
            }
            // 存储文件或返回字符串
            String priKeyName = "应用私钥" + keyType.getLength();
            String pubKeyName = "应用公钥" + keyType.getLength();

            String privateCertPath = null;
            String publicCertPath = null;
            String privateKeyPath = null;

            String successMessage;
            if ("file".equals(request.getStorageType())) {
                privateKeyPath = SupportUtils.writeKeyFile(new String[]{priKeyName, pubKeyName}, result, keyType);
                privateCertPath = privateKeyPath + priKeyName + ".txt";
                publicCertPath = privateKeyPath + pubKeyName + ".txt";
                successMessage = "密钥生成成功，文件保存至[" + privateKeyPath + "]";
            } else {
                successMessage = "密钥生成成功";
            }

            response.setMessage(successMessage);
            response.setPrivateKey(result[0]);
            response.setPublicKey(result[1]);
            response.setPrivateCertPath(privateCertPath);
            response.setPublicCertPath(publicCertPath);
            return response;

        } catch (Exception e) {
            response.setMessage("生成密钥异常：" + e.getMessage());
            return response;
        }
    }
}
