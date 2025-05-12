/*
 * Copyright: Copyright (c)2011
 * Company: 易宝支付(YeePay)
 */
package com.yeepay.yop.mcp.tool;

import com.yeepay.yop.mcp.config.Config;
import com.yeepay.yop.mcp.model.*;
import com.yeepay.yop.mcp.utils.*;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * title: <br>
 * description: 描述<br>
 * Copyright: Copyright (c)2014<br>
 * Company: 易宝支付(YeePay)<br>
 *
 * @author wenbo.fan-1
 * @version 1.0.0
 * @since 2025/5/9 14:35
 */
@Service
public class DownloadCertTool {
    /**
     * 标记p10文件是否已经生成
     */
    private boolean p10Generated = false;

    @Tool(description = "根据密钥算法、CFCA证书的序列号、授权码、非对称密钥对（公钥和私钥）、密码，下载该证书，并保存到本地路径")
    public DownloadCertResponse downloadCert(DownloadCertRequest request) {
        DownloadCertResponse response = new DownloadCertResponse();
        // 解析密钥类型
        KeyType keyType;
        if ("RSA".equalsIgnoreCase(request.getAlgorithm())) {
            keyType = KeyType.RSA2048;
        } else if ("SM2".equalsIgnoreCase(request.getAlgorithm())) {
            keyType = KeyType.SM2;
        } else {
            throw new IllegalArgumentException("不支持的密钥算法: " + request.getAlgorithm());
        }
        String serialNo = request.getSerialNo();
        String authCode = request.getAuthCode();
        String priKey = request.getPrivateKey();
        String pubKey = request.getPublicKey();
        String pwd = request.getPwd();
        CheckResult checkResult = checkInput(serialNo, authCode, keyType, priKey, pubKey, pwd);
        if (!checkResult.result) {
            response.setMessage(checkResult.msg);
            return response;
        }
        try {
            if (!p10Generated && !checkKey(priKey, pubKey, keyType)) {
                response.setMessage("商户公私钥不匹配");
                return response;
            }
        } catch (Exception exception) {
            response.setMessage("密钥解析异常");
            return response;
        }
        String cerReq;
        if (p10Generated) {
            cerReq = priKey;
        } else {
            cerReq = CertUtils.genP10(priKey, pubKey, keyType);
        }
        String certPath = null;
        if (KeyType.SM2.equals(keyType)) {
            certPath = Config.SM2_CERT_SAVE_PATH;
        } else if (KeyType.RSA2048.equals(keyType)) {
            certPath = Config.RSA_CERT_SAVE_PATH;
        }
        String priCertPath = certPath + serialNo + ".pfx";
        String pubCertPath = certPath + serialNo + ".cer";
        if (SupportUtils.isFileExists(priCertPath) && SupportUtils.isFileExists(pubCertPath)) {
            response.setMessage("本地证书已存在，请打开下载目录查看");
            response.setPfxCertPath(priCertPath);
            response.setPubCertPath(pubCertPath);
            return response;
        }
        try {
            String cert;
            if (SupportUtils.isFileExists(pubCertPath)) {
                cert = SupportUtils.readFileAsString(pubCertPath);
            } else {
                CertDownloadResult certDownloadResult = downloadCert(serialNo, authCode, cerReq);
                if (StringUtils.isNotEmpty(certDownloadResult.getErrorMsg())) {
                    response.setMessage(certDownloadResult.getErrorMsg());
                    return response;
                }
                cert = certDownloadResult.getCert();
            }
            if (!checkCert(priKey, cert, keyType)) {
                response.setMessage("证书已下载过，且证书与输入的私钥不匹配，请核对");
                return response;
            }
            CertUtils.makePubCert(cert, serialNo, certPath);
            if (!p10Generated) {
                CertUtils.makePfxCert(priKey, cert, keyType, pwd, serialNo, certPath);
            }
            response.setMessage("CFCA证书激活并下载成功");
            response.setPfxCertPath(priCertPath);
            response.setPubCertPath(pubCertPath);
            return response;
        } catch (Exception exception) {
            response.setMessage("系统异常，请稍后重试");
            return response;
        }
    }

    private CheckResult checkInput(String serialNo, String authCode, KeyType keyType, String priKey, String pubKey, String pwd) {
        CheckResult checkResult = new CheckResult();
        if (StringUtils.isEmpty(serialNo)) {
            checkResult.msg = "证书序列号格式有误，请重新输入！";
            checkResult.result = false;
            return checkResult;
        }
        if (keyType == null) {
            checkResult.msg = "证书序列号格式有误，请重新输入！";
            checkResult.result = false;
            return checkResult;
        }

        if (StringUtils.isEmpty(authCode)) {
            checkResult.msg = "证书授权码格式有误，请重新输入！";
            checkResult.result = false;
            return checkResult;
        }
        if (p10Generated && StringUtils.isEmpty(priKey)) {
            checkResult.msg = "PKCS申请书格式有误，请重新输入！";
            checkResult.result = false;
            return checkResult;
        }
        if (p10Generated && StringUtils.isNotEmpty(priKey)) {
            checkResult.result = true;
            return checkResult;
        }
        if (StringUtils.isEmpty(priKey)) {
            checkResult.msg = "商户私钥格式有误，请重新输入！";
            checkResult.result = false;
            return checkResult;
        }
        if (StringUtils.isEmpty(pubKey)) {
            checkResult.msg = "商户公钥格式有误，请重新输入！";
            checkResult.result = false;
            return checkResult;

        }
        if (StringUtils.isEmpty(pwd)) {
            checkResult.result = false;
            checkResult.msg = "请输入密码！";
            return checkResult;
        }
        if (pwd.length() > 16) {
            checkResult.result = false;
            checkResult.msg = "密码格式有误，请重新输入！";
            return checkResult;
        }
        checkResult.result = true;
        return checkResult;
    }

    private boolean checkKey(String priKey, String pubKey, KeyType keyType) {
        try {
            PublicKey publicKey;
            if (KeyType.SM2.equals(keyType)) {
                publicKey = Sm2Utils.buildECPublicKeyByPrivateKey((BCECPrivateKey) Sm2Utils.string2PrivateKey(priKey));
                if (!Base64Utils.encode(publicKey.getEncoded()).equals(pubKey)) {
                    return false;
                }
            } else if (KeyType.RSA2048.equals(keyType)) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64Utils.decode(priKey)));
                RSAPrivateKeySpec priv = kf.getKeySpec(privateKey, RSAPrivateKeySpec.class);

                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(priv.getModulus(), BigInteger.valueOf(65537));
                publicKey = kf.generatePublic(keySpec);
            } else {
                return false;
            }
            return (Base64Utils.encode(publicKey.getEncoded())).equals(pubKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private CertDownloadResult downloadCert(String serialNo, String authCode, String certReq) throws Exception {
        String host = ConfigUtils.getHost();
        String keyAlgQueryUrl = host + "/yop-developer-center/apis/cfca/cert/download";
        Map<Object, Object> param = new HashMap<>();
        param.put("serialNo", serialNo);
        param.put("authCode", authCode);
        param.put("certReq", certReq);
        param.put("toolsVersion", Config.TOOLS_VERSION);
        String response = HttpUtils.getResponse(keyAlgQueryUrl, param, getHeaders());
        Map map = JsonUtils.jsonToPojo(response, Map.class);
        if (map.get("code").equals("000000")) {
            Map dataMap = (Map) map.get("data");
            return new CertDownloadResult().withCert("-----BEGIN CERTIFICATE-----\n" + dataMap.get("cert").toString() + "\n-----END CERTIFICATE-----");
        } else {
            return new CertDownloadResult().withErrorMsg((String) map.get("message"));
        }
    }

    private Map getHeaders() {
        String basic = "keytools:keytools";
        Map<Object, Object> headers = new HashMap();
        headers.put("Authorization", "Basic " + Base64Utils.encode(basic.getBytes()));
        return headers;
    }

    private boolean checkCert(String priKey, String cert, KeyType keyType) throws Exception {
        if (p10Generated) {
            return true;
        }
        X509Certificate x509Certificate = CertUtils.getX509Certificate(cert.getBytes());
        String pubKey = Base64Utils.encode(x509Certificate.getPublicKey().getEncoded());
        String plainText = "a=123";
        boolean verifyTrue;
        if (KeyType.RSA2048.equals(keyType)) {
            String signature = RSA.sign(plainText, priKey, "SHA256withRSA", "UTF-8");
            verifyTrue = RSA.verify(plainText, signature, pubKey, "SHA256withRSA", "UTF-8");
        } else if (KeyType.SM2.equals(keyType)) {
            String signature = Sm2Utils.sign(plainText, (BCECPrivateKey) Sm2Utils.string2PrivateKey(priKey));
            verifyTrue = Sm2Utils.verifySign(plainText, signature, (BCECPublicKey) Sm2Utils.string2PublicKey(pubKey));

        } else {
            throw new Exception("unsupported keyType");
        }
        return verifyTrue;
    }
}
