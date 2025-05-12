package com.yeepay.yop.mcp;

import com.yeepay.yop.mcp.tool.DownloadCertTool;
import com.yeepay.yop.mcp.tool.KeyGenTool;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.security.Security;

@SpringBootApplication
public class Application {
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            int requestedPosition = 2;
            int actualPosition = Security.insertProviderAt(new BouncyCastleProvider(), 9999);
            System.out.println("Requested to add BouncyCastleProvider at position: " + requestedPosition +
                    " and was actually added at position: " + actualPosition);
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public ToolCallbackProvider keyGen(KeyGenTool keyGenTool) {
        return MethodToolCallbackProvider.builder().toolObjects(keyGenTool).build();
    }

    @Bean
    public ToolCallbackProvider downloadCert(DownloadCertTool downloadCertTool) {
        return MethodToolCallbackProvider.builder().toolObjects(downloadCertTool).build();
    }
}
