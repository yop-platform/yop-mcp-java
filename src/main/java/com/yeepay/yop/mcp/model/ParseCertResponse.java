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
 * @since 2025/5/12 11:22
 */
@Data
public class ParseCertResponse extends BaseResponse {
    private static final long serialVersionUID = -1L;

    /**
     * Base64 编码后的私钥字符串
     */
    private String privateKey;

    /**
     * Base64 编码后的公钥字符串
     */
    private String publicKey;

}
