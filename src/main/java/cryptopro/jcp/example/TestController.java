package cryptopro.jcp.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    private final String SAMPLE_TEXT = "test sugnature";

    @Autowired
    private CertificateService certificateService;

    @RequestMapping("/")
    String home() throws Exception {
        StringBuilder response = new StringBuilder();
        final byte[] signEL = certificateService.sign(Constants.SIGN_EL_ALG_2012_256,
                SAMPLE_TEXT.getBytes());
        response.append("Value of signature (signEL) is:");
        response.append(System.getProperty("line.separator"));
        response.append(Constants.toHexString(signEL));
        response.append(System.getProperty("line.separator"));
        // Проверка подписи
        final boolean signELver = certificateService.verify(Constants.SIGN_EL_ALG_2012_256,
                SAMPLE_TEXT.getBytes(), signEL);
        response.append("Signature verifies (signEL) is: " + signELver);
        return response.toString();
    }
}
