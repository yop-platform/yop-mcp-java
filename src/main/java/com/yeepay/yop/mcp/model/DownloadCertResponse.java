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
 * @since 2025/5/9 15:13
 */
@Data
public class DownloadCertResponse extends BaseResponse {
    private static final long serialVersionUID = -1L;
    /**
     * 私钥证书（.pfx）路径
     */
    private String pfxCertPath;

    /**
     * 公钥证书（.cer）路径
     */
    private String pubCertPath;
}
