package com.yeepay.yop.mcp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

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

//	@Bean
//	public ToolCallbackProvider weatherTools(WeatherService weatherService) {
//		return MethodToolCallbackProvider.builder().toolObjects(weatherService).build();
//	}
}
