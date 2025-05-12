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
 * @since 2025/5/9 15:23
 */
@Data
public class CertDownloadResult implements Serializable {
    private static final long serialVersionUID = -1L;

    /**
     * 证书内容
     */
    private String cert;

    /**
     * 错误信息
     */
    private String errorMsg;

    public CertDownloadResult withCert(String cert) {
        this.cert = cert;
        return this;
    }

    public CertDownloadResult withErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
        return this;
    }
}
