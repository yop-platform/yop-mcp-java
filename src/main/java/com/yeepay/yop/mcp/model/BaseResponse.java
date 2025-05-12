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
 * @since 2025/5/9 11:07
 */
@Data
public class BaseResponse implements Serializable {
    private static final long serialVersionUID = -1L;

    /**
     * 响应消息
     */
    private String message;
}
