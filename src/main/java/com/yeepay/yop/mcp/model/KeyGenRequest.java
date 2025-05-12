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
 * @since 2025/5/9 11:01
 */
@Data
public class KeyGenRequest implements Serializable {
    private static final long serialVersionUID = -1L;
    /**
     * 密钥算法
     */
    private String algorithm = "RSA";

    /**
     * 密钥格式
     */
    private String format = "PKCS8";

    /**
     * 密钥存储类型
     */
    private String storageType = "file";
}
