/*
 * Copyright: Copyright (c)2011
 * Company: 易宝支付(YeePay)
 */
package com.yeepay.yop.mcp.utils;

import com.yeepay.yop.mcp.config.Config;
import org.apache.commons.lang3.StringUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * title: <br>
 * description: 取可配置信息的工具类<br>
 * Copyright: Copyright (c)2014<br>
 * Company: 易宝支付(YeePay)<br>
 *
 * @author wenbo.fan-1
 * @version 1.0.0
 * @since 2021/12/3 3:22 下午
 */
public class ConfigUtils {
    public static final String YOP_TEST_CONFIG_FILE = "yop-test.properties";

    /**
     * 获取host（下载证书时需要调用http接口）
     *
     * @return
     */
    public static String getHost() {
        String host = "https://mp.yeepay.com";
        if (SupportUtils.isFileExists(Config.QA_HOST_PATH + YOP_TEST_CONFIG_FILE)) {
            String configHost = getProperties().getProperty("host");
            if (StringUtils.isNotEmpty(configHost)) {
                host = configHost;
            }
        }
        return host;
    }

    public static boolean enableDownloadActivatedCert() {
        boolean enable = false;
        if (SupportUtils.isFileExists(Config.QA_HOST_PATH + YOP_TEST_CONFIG_FILE)) {
            enable = Boolean.parseBoolean(getProperties().getProperty("downloadActivatedCert"));
        }
        return enable;
    }

    private static Properties getProperties() {
        Properties properties = new Properties();
        try {
            FileInputStream fin = new FileInputStream(Config.QA_HOST_PATH + YOP_TEST_CONFIG_FILE);
            properties.load(fin);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return properties;
    }
}
