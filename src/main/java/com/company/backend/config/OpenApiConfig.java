package com.company.backend.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;   // <-- keep this for annotations

import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenApiConfig - Swagger/OpenAPI configuration
 * Configures API documentation with JWT authentication
 *
 * REUSABILITY:
 * This configuration is reusable across different projects
 * Update the API info and servers as needed
 */
@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Onboarding Suite API",
                version = "1.0.0",
                description = "REST API for Onboarding Suite - Merchant Application Management System with JWT Authentication",
                contact = @Contact(
                        name = "Development Team",
                        email = "dev@laitusneo.com",
                        url = "https://laitusneo.com"
                ),
                license = @License(
                        name = "Apache 2.0",
                        url = "https://www.apache.org/licenses/LICENSE-2.0.html"
                )
        ),
        servers = {
                @Server(
                        description = "Local Development Server",
                        url = "http://localhost:8081"
                ),
                @Server(
                        description = "Staging Server",
                        url = "https://staging.laitusneo.com"
                ),
                @Server(
                        description = "Production Server",
                        url = "https://api.laitusneo.com"
                )
        }
)
@SecurityScheme(
        name = "bearerAuth",
        description = "JWT Authentication - Use format: Bearer {token}",
        scheme = "bearer",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {

    /**
     * Custom OpenAPI configuration to ensure correct server URL
     *
     * @return OpenAPI configuration
     */
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .addServersItem(new io.swagger.v3.oas.models.servers.Server()  // <-- fully qualified name
                        .url("http://localhost:8081")
                        .description("Local Development Server"));
    }
}
