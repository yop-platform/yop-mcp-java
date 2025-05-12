/*
 * Copyright: Copyright (c)2011
 * Company: 易宝支付(YeePay)
 */
package com.yeepay.yop.mcp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.yeepay.yop.mcp.model.DownloadCertRequest;
import com.yeepay.yop.mcp.model.DownloadCertResponse;
import com.yeepay.yop.mcp.model.KeyGenRequest;
import com.yeepay.yop.mcp.model.KeyGenResponse;
import com.yeepay.yop.mcp.tool.DownloadCertTool;
import com.yeepay.yop.mcp.tool.KeyGenTool;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * title: <br>
 * description: 描述<br>
 * Copyright: Copyright (c)2014<br>
 * Company: 易宝支付(YeePay)<br>
 *
 * @author wenbo.fan-1
 * @version 1.0.0
 * @since 2025/5/9 14:11
 */
@SpringBootTest
class ApplicationTests {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            int requestedPosition = 2;
            int actualPosition = Security.insertProviderAt(new BouncyCastleProvider(), 9999);
            System.out.println("Requested to add BouncyCastleProvider at position: " + requestedPosition +
                    " and was actually added at position: " + actualPosition);
        }
    }

    JsonMapper jsonMapper = JsonMapper.builder().build();

    @Autowired
    private KeyGenTool keyGenTool;

    @Autowired
    private DownloadCertTool downloadCertTool;

    @Test
    void kenGen() throws JsonProcessingException {
        KeyGenRequest keyGenRequest = new KeyGenRequest();
        keyGenRequest.setAlgorithm("SM2");
        keyGenRequest.setFormat("PKCS8");
        keyGenRequest.setStorageType("string");
        KeyGenResponse keyGenResponse = keyGenTool.genKeypair(keyGenRequest);
        System.out.println(jsonMapper.writeValueAsString(keyGenResponse));
        assertThat(keyGenResponse.getPrivateKey()).isNotBlank();
        assertThat(keyGenResponse.getPublicKey()).isNotBlank();
    }

    @Test
    void downloadCert() throws JsonProcessingException {
        DownloadCertRequest downloadCertRequest = new DownloadCertRequest();
        downloadCertRequest.setAlgorithm("SM2");
        downloadCertRequest.setSerialNo("4928999747");
        downloadCertRequest.setAuthCode("RKTFEKXN5H");
        downloadCertRequest.setPrivateKey("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgSFdFggHZv240SjAgL2RF93sGOT+l2ewiS1K5W5uNbGigCgYIKoEcz1UBgi2hRANCAATDFmDAXwWJLbnRAwoh4GT7bxXJFjUnefhcU3nCM/wamrRPztBpZFGBdHqycxjrBIphQd+fr6q5v11uGhRiH5o9");
        downloadCertRequest.setPublicKey("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEwxZgwF8FiS250QMKIeBk+28VyRY1J3n4XFN5wjP8Gpq0T87QaWRRgXR6snMY6wSKYUHfn6+qub9dbhoUYh+aPQ==");
        downloadCertRequest.setPwd("qwertyuiop[]");
        DownloadCertResponse downloadCertResponse = downloadCertTool.downloadCert(downloadCertRequest);
        System.out.println(jsonMapper.writeValueAsString(downloadCertResponse));
    }
}
