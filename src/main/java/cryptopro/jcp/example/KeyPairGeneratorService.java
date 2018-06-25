package cryptopro.jcp.example;

import org.springframework.stereotype.Service;
import ru.CryptoPro.JCP.params.AlgIdSpec;
import ru.CryptoPro.JCP.params.OID;
import java.security.KeyPair;

/**
 * Сервис для генерации ключевой пары в соответствии с
 * алгоритмом ГОСТ Р 34.10-2001
 */
@Service
public class KeyPairGeneratorService {
    /**
     * генерирование ключевой пары
     *
     * @param algorithm алгоритм
     * @return ключевая пара
     * @throws Exception /
     */
    public KeyPair genKey(String algorithm)
            throws Exception {

        // создание генератора ключевой пары
        final java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance(algorithm);

        // генерирование ключевой пары
        return keyGen.generateKeyPair();
    }

    /**
     * генерирование ключевой пары с параметрами
     *
     * @param algorithm алгоритм
     * @return ключевая пара
     * @throws Exception /
     */
    public KeyPair genKeyWithParams(String algorithm, OID keyOid,
                                           OID signOid, OID digestOid, OID cryptOid) throws Exception {

        // создание генератора ключевой пары ЭЦП
        final java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance(algorithm);

        // определение параметров генератора ключевой пары
        final AlgIdSpec keyParams =
                new AlgIdSpec(keyOid, signOid, digestOid, cryptOid);
        keyGen.initialize(keyParams);

        // генерирование ключевой пары
        return keyGen.generateKeyPair();
    }

}
