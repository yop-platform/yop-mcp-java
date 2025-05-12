/*
 * Copyright: Copyright (c)2011
 * Company: 易宝支付(YeePay)
 */
package com.yeepay.yop.mcp.model;

import lombok.Data;

/**
 * title: <br>
 * description: 描述<br>
 * Copyright: Copyright (c)2014<br>
 * Company: 易宝支付(YeePay)<br>
 *
 * @author wenbo.fan-1
 * @version 1.0.0
 * @since 2025/5/9 11:03
 */
@Data
public class KeyGenResponse extends BaseResponse {
    private static final long serialVersionUID = -1L;

    /**
     * 私钥
     */
    private String privateKey;

    /**
     * 公钥
     */
    private String publicKey;

    /**
     * 私钥证书路径
     */
    private String privateCertPath;

    /**
     * 公钥证书路径
     */
    private String publicCertPath;
}
