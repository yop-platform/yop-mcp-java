package com.yeepay.yop.mcp.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.BitSet;
import java.util.Map;

/**
 * title: <br>
 * description:描述<br>
 * Copyright: Copyright (c)2011<br>
 * Company: 易宝支付(YeePay)<br>
 *
 * @author dreambt
 * @version 1.0.0
 * @since 2018/1/10 上午11:23
 */
public final class HttpUtils {

    private static final String DEFAULT_ENCODING = "UTF-8";

    private static BitSet URI_UNRESERVED_CHARACTERS = new BitSet();
    private static String[] PERCENT_ENCODED_STRINGS = new String[256];

    /**
     * Regex which matches any of the sequences that we need to fix up after URLEncoder.encode().
     */
    static {
        for (int i = 'a'; i <= 'z'; i++) {
            URI_UNRESERVED_CHARACTERS.set(i);
        }
        for (int i = 'A'; i <= 'Z'; i++) {
            URI_UNRESERVED_CHARACTERS.set(i);
        }
        for (int i = '0'; i <= '9'; i++) {
            URI_UNRESERVED_CHARACTERS.set(i);
        }
        URI_UNRESERVED_CHARACTERS.set('-');
        URI_UNRESERVED_CHARACTERS.set('.');
        URI_UNRESERVED_CHARACTERS.set('_');
        URI_UNRESERVED_CHARACTERS.set('~');

        for (int i = 0; i < PERCENT_ENCODED_STRINGS.length; ++i) {
            PERCENT_ENCODED_STRINGS[i] = String.format("%%%02X", i);
        }
    }

    private HttpUtils() {
        // do nothing
    }

    /**
     * Normalize a string for use in url path. The algorithm is:
     * <p>
     * <p>
     * <ol>
     * <li>Normalize the string</li>
     * <li>replace all "%2F" with "/"</li>
     * <li>replace all "//" with "/%2F"</li>
     * </ol>
     * <p>
     * <p>
     * object key can contain arbitrary characters, which may result double slash in the url path. Apache http
     * client will replace "//" in the path with a single '/', which makes the object key incorrect. Thus we replace
     * "//" with "/%2F" here.
     *
     * @param path the path string to normalize.
     * @return the normalized path string.
     * @see #normalize(String)
     */
    public static String normalizePath(String path) {
        return normalize(path).replace("%2F", "/");
    }

    /**
     * Normalize a string for use in web service APIs. The normalization algorithm is:
     * <p>
     * <ol>
     * <li>Convert the string into a UTF-8 byte array.</li>
     * <li>Encode all octets into percent-encoding, except all URI unreserved characters per the RFC 3986.</li>
     * </ol>
     * <p>
     * <p>
     * All letters used in the percent-encoding are in uppercase.
     *
     * @param value the string to normalize.
     * @return the normalized string.
     * @throws UnsupportedEncodingException
     */
    public static String normalize(String value) {
        try {
            StringBuilder builder = new StringBuilder();
            for (byte b : value.getBytes(DEFAULT_ENCODING)) {
                if (URI_UNRESERVED_CHARACTERS.get(b & 0xFF)) {
                    builder.append((char) b);
                } else {
                    builder.append(PERCENT_ENCODED_STRINGS[b & 0xFF]);
                }
            }
            return builder.toString();
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getCanonicalURIPath(String path) {
        if (path == null) {
            return "/";
        } else if (path.startsWith("/")) {
            return normalizePath(path);
        } else {
            return "/" + normalizePath(path);
        }
    }

    /**
     * 获取接口返回的结果(GET).
     *
     * @param getUrl        请求接口的url
     * @param requestParam  请求接口的参数
     * @param requestHeader 请求接口的Header
     * @return 请求接口的返回值
     * @throws IOException the io exception
     */
    public static String getResponse(String getUrl, Map<Object, Object> requestParam, Map<Object, Object> requestHeader) throws IOException {

        String param = "";
        if (requestParam != null) {
            for (Map.Entry<Object, Object> entry : requestParam.entrySet()) {
                if ("".equals(param) || param == "") {
                    param = entry.getKey() + "=" + URLEncoder.encode(entry.getValue().toString(), "utf-8");
                } else {
                    param = param + "&" + entry.getKey() + "=" + URLEncoder.encode(entry.getValue().toString(), "utf-8");
                }
            }
        }
        getUrl = getUrl + "?" + param;
        URL url = new URL(getUrl);
        // 将url 以 open方法返回的urlConnection  连接强转为HttpURLConnection连接  (标识一个url所引用的远程对象连接)
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        if (requestHeader != null) {
            // 设置 Header 信息
            for (Map.Entry<Object, Object> entry : requestHeader.entrySet()) {
                connection.setRequestProperty(entry.getKey().toString(), entry.getValue().toString());
            }
        }
        connection.connect();

        // 获取输入流
        BufferedReader br;
        if (connection.getResponseCode() == 200) {
            br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "UTF-8"));
        } else {
            br = new BufferedReader(new InputStreamReader(connection.getErrorStream(), "UTF-8"));
        }
        String line;
        StringBuilder sb = new StringBuilder();
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();
        connection.disconnect();
        return sb.toString();
    }

}
