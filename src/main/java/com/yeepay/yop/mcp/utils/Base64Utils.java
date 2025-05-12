/*
 * Copyright: Copyright (c)2011
 * Company: 易宝支付(YeePay)
 */
package com.yeepay.yop.mcp.utils;

import org.apache.commons.codec.binary.Base64;

/**
 * title: <br>
 * description: 描述<br>
 * Copyright: Copyright (c)2014<br>
 * Company: 易宝支付(YeePay)<br>
 *
 * @author wenbo.fan-1
 * @version 1.0.0
 * @since 2021/9/9 8:26 下午
 */
public class Base64Utils {
    public static String encode(byte[] bytes) {
        return new String(Base64.encodeBase64(bytes));
    }

    public static String urlSafeEncode(byte[] bytes) {
        return Base64.encodeBase64URLSafeString(bytes);
    }

    public static byte[] decode(String base64Str) {
        return Base64.decodeBase64(base64Str);
    }
}
