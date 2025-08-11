FROM maven:3.8.5-openjdk-11 AS build

WORKDIR /app

# Create pom.xml
RUN echo '<?xml version="1.0" encoding="UTF-8"?>\n\
<project xmlns="http://maven.apache.org/POM/4.0.0"\n\
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n\
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0\n\
         http://maven.apache.org/xsd/maven-4.0.0.xsd">\n\
    <modelVersion>4.0.0</modelVersion>\n\
    <groupId>com.vulnerable</groupId>\n\
    <artifactId>deserialization-lab</artifactId>\n\
    <version>1.0.0</version>\n\
    <dependencies>\n\
        <dependency>\n\
            <groupId>org.springframework.boot</groupId>\n\
            <artifactId>spring-boot-starter-web</artifactId>\n\
            <version>2.5.0</version>\n\
        </dependency>\n\
        <dependency>\n\
            <groupId>commons-collections</groupId>\n\
            <artifactId>commons-collections</artifactId>\n\
            <version>3.2.1</version>\n\
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

# Create vulnerable Java application
RUN mkdir -p src/main/java/com/vulnerable && \
    echo 'package com.vulnerable;\n\
\n\
import org.springframework.boot.SpringApplication;\n\
import org.springframework.boot.autoconfigure.SpringBootApplication;\n\
import org.springframework.web.bind.annotation.*;\n\
import java.io.*;\n\
import java.util.Base64;\n\
\n\
@SpringBootApplication\n\
@RestController\n\
public class DeserializationApp {\n\
    \n\
    public static void main(String[] args) {\n\
        SpringApplication.run(DeserializationApp.class, args);\n\
    }\n\
    \n\
    @GetMapping("/")\n\
    public String home() {\n\
        return "<html><body>" +\n\
               "<h1>Java Deserialization Lab</h1>" +\n\
               "<h2>Vulnerable Endpoints:</h2>" +\n\
               "<ul>" +\n\
               "<li>POST /deserialize - Deserialize base64 encoded object</li>" +\n\
               "<li>GET /serialize?data=test - Serialize string to base64</li>" +\n\
               "</ul>" +\n\
               "<h3>Test Serialization:</h3>" +\n\
               "<form method=\"POST\" action=\"/deserialize\">" +\n\
               "<textarea name=\"data\" rows=\"10\" cols=\"50\">rO0ABXQABHRlc3Q=</textarea><br>" +\n\
               "<input type=\"submit\" value=\"Deserialize\">" +\n\
               "</form>" +\n\
               "</body></html>";\n\
    }\n\
    \n\
    @PostMapping("/deserialize")\n\
    public String deserialize(@RequestParam String data) {\n\
        try {\n\
            byte[] bytes = Base64.getDecoder().decode(data);\n\
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);\n\
            \n\
            // VULNERABLE: Deserializing untrusted data!\n\
            ObjectInputStream ois = new ObjectInputStream(bis);\n\
            Object obj = ois.readObject();\n\
            ois.close();\n\
            \n\
            return "Deserialized object: " + obj.toString();\n\
        } catch (Exception e) {\n\
            return "Error: " + e.getMessage();\n\
        }\n\
    }\n\
    \n\
    @GetMapping("/serialize")\n\
    public String serialize(@RequestParam String data) {\n\
        try {\n\
            ByteArrayOutputStream bos = new ByteArrayOutputStream();\n\
            ObjectOutputStream oos = new ObjectOutputStream(bos);\n\
            oos.writeObject(data);\n\
            oos.close();\n\
            \n\
            String base64 = Base64.getEncoder().encodeToString(bos.toByteArray());\n\
            return "Serialized data (base64): " + base64;\n\
        } catch (Exception e) {\n\
            return "Error: " + e.getMessage();\n\
        }\n\
    }\n\
}' > src/main/java/com/vulnerable/DeserializationApp.java

# Build the application
RUN mvn clean package -DskipTests

FROM openjdk:11-jre-slim
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"] 