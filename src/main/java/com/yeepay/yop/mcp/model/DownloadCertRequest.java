/*
 * Copyright: Copyright (c)2011
 * Company: 易宝支付(YeePay)
 */
package com.yeepay.yop.mcp.model;

import lombok.Data;

import java.io.Serializable;

/**
 * title: <br>
 * description: 描述<br>
 * Copyright: Copyright (c)2014<br>
 * Company: 易宝支付(YeePay)<br>
 *
 * @author wenbo.fan-1
 * @version 1.0.0
 * @since 2025/5/9 15:05
 */
@Data
public class DownloadCertRequest implements Serializable {
    private static final long serialVersionUID = -1L;

    /**
     * 密钥算法
     */
    private String algorithm = "RSA";

    /**
     * 证书序列号
     */
    private String serialNo;

    /**
     * 证书授权码
     */
    private String authCode;

    /**
     * Base64 编码后的私钥字符串
     */
    private String privateKey;

    /**
     * Base64 编码后的公钥字符串
     */
    private String publicKey;

    /**
     * 证书密码
     */
    private String pwd;

}
