package cryptopro.jcp.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableAutoConfiguration
public class Application {

    @Autowired
    private CertificateService certificateService;

    public static void main(String...args) {
        SpringApplication.run(Application.class, args);
    }
}
