FROM maven:3.8.5-openjdk-11 AS build

WORKDIR /app

# Create a minimal Spring Boot application with vulnerabilities
RUN echo '<?xml version="1.0" encoding="UTF-8"?>\n\
<project xmlns="http://maven.apache.org/POM/4.0.0"\n\
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n\
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 \n\
         http://maven.apache.org/xsd/maven-4.0.0.xsd">\n\
    <modelVersion>4.0.0</modelVersion>\n\
    <parent>\n\
        <groupId>org.springframework.boot</groupId>\n\
        <artifactId>spring-boot-starter-parent</artifactId>\n\
        <version>2.5.0</version>\n\
    </parent>\n\
    <groupId>com.vulnerable</groupId>\n\
    <artifactId>spring-vulnerable</artifactId>\n\
    <version>1.0.0</version>\n\
    <properties>\n\
        <java.version>11</java.version>\n\
    </properties>\n\
    <dependencies>\n\
        <dependency>\n\
            <groupId>org.springframework.boot</groupId>\n\
            <artifactId>spring-boot-starter-web</artifactId>\n\
        </dependency>\n\
        <dependency>\n\
            <groupId>org.springframework.boot</groupId>\n\
            <artifactId>spring-boot-starter-actuator</artifactId>\n\
        </dependency>\n\
    </dependencies>\n\
    <build>\n\
        <plugins>\n\
            <plugin>\n\
                <groupId>org.springframework.boot</groupId>\n\
                <artifactId>spring-boot-maven-plugin</artifactId>\n\
            </plugin>\n\
        </plugins>\n\
    </build>\n\
</project>' > pom.xml

# Create main application class
RUN mkdir -p src/main/java/com/vulnerable && \
    echo 'package com.vulnerable;\n\
\n\
import org.springframework.boot.SpringApplication;\n\
import org.springframework.boot.autoconfigure.SpringBootApplication;\n\
import org.springframework.web.bind.annotation.*;\n\
import java.io.*;\n\
\n\
@SpringBootApplication\n\
@RestController\n\
public class VulnerableApp {\n\
    \n\
    public static void main(String[] args) {\n\
        SpringApplication.run(VulnerableApp.class, args);\n\
    }\n\
    \n\
    @GetMapping("/execute")\n\
    public String execute(@RequestParam String cmd) {\n\
        try {\n\
            // Vulnerable to command injection\n\
            Process process = Runtime.getRuntime().exec(cmd);\n\
            BufferedReader reader = new BufferedReader(\n\
                new InputStreamReader(process.getInputStream()));\n\
            StringBuilder output = new StringBuilder();\n\
            String line;\n\
            while ((line = reader.readLine()) != null) {\n\
                output.append(line).append("\\n");\n\
            }\n\
            return output.toString();\n\
        } catch (Exception e) {\n\
            return "Error: " + e.getMessage();\n\
        }\n\
    }\n\
}' > src/main/java/com/vulnerable/VulnerableApp.java

# Configure application to expose actuator endpoints (security misconfiguration)
RUN mkdir -p src/main/resources && \
    echo 'server.port=8080\n\
management.endpoints.web.exposure.include=*\n\
management.endpoint.health.show-details=always\n\
spring.security.user.name=admin\n\
spring.security.user.password=admin' > src/main/resources/application.properties

# Build the application
RUN mvn clean package -DskipTests

FROM openjdk:11-jre-slim
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"] 