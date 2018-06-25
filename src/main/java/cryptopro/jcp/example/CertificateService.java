package cryptopro.jcp.example;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import com.objsys.asn1j.runtime.Asn1Boolean;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Extension;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.Random.BioRandomConsole;
import ru.CryptoPro.JCPRequest.GostCertificateRequest;

import javax.annotation.PostConstruct;

/**
 * Сервис, для работы с сертификатами и подписями. Содержит методы чтения сертификата, записи сертификата и приватного ключа,
 * генерации электронной подписи и проверки электронной подписи.
 */
@Service
public class CertificateService {
    /**
     * уникальное имя записываемого сертификата
     */
    @Value("${certificate.alias_2012_256}")
    private String ALIAS_2012_256;
    /**
     * имя субъекта для генерирования запроса на сертификат
     */
    @Value("${certificate.dname_2012_256}")
    private String DNAME_2012_256;
    /**
     * http-адрес центра центра сертификации
     */
    @Value("${ocsp.http_address}")
    private String HTTP_ADDRESS;
    /**
     * путь к файлу хранилища сертификатов
     */
    @Value("${certificate.store_path_2012_256}")
    private String STORE_PATH_2012_256;
    /**
     * имя ключевого носителя для инициализации хранилища
     */
    private final String STORE_TYPE = Constants.KEYSTORE_TYPE;
    /**
     * устанавливаемый пароль на хранилище сертификатов
     */
    private final char[] STORE_PASS = new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    /**
     * алгоритм ключа (ГОСТ Р 34.10-2012, 256)
     */
    private static final String KEY_ALG_2012_256 = Constants.SIGN_KEY_PAIR_ALG_2012_256;

    @Autowired
    private KeyPairGeneratorService keyPairGeneratorService;

    /**
     * Инициализация хранилища сертификатов, если оно не существует.
     * В течении инициализации создается пара ключей(приватный и публичный), и сохраняются в хранилище,
     * которое содержится в файле STORE_PATH_2012_256
     * @throws Exception
     */
    @PostConstruct
    private void initCertificatesStorage() throws Exception {
        BioRandomConsole.main(null);
        Optional<Certificate> optional = readCertSample(STORE_PATH_2012_256, ALIAS_2012_256);
        if (!optional.isPresent()) {
            //получение сертификата и запись его в хранилище
            writeCertSample(KEY_ALG_2012_256, JCP.GOST_SIGN_2012_256_NAME,
                    ALIAS_2012_256, STORE_PATH_2012_256, DNAME_2012_256);
            System.out.println("Storage with certificate and private key " + STORE_PATH_2012_256 + " has been created");
        } else {
            System.out.println("Storage " + STORE_PATH_2012_256 + " exists");
        }
    }

    /**
     * Возвращает сертификат
     * @return сертификат из хранилища, определенного в файле STORE_PATH_2012_256
     * @throws Exception
     */
    public Certificate getCertificate() throws Exception {
        Optional<Certificate> optional = readCertSample(STORE_PATH_2012_256, ALIAS_2012_256);
        return optional.orElse(null);
    }

    /**
     * Создание подписи
     *
     * @param alghorithmName алгоритм подписи
     * @param data подписываемые данные
     * @return подпись
     * @throws Exception /
     */
    public byte[] sign(String alghorithmName,
                               byte[] data) throws Exception {
        return sign(alghorithmName,getPrivateKey(STORE_PATH_2012_256, ALIAS_2012_256), data);
    }

    /**
     * Проверка подписи на открытом ключе
     *
     * @param alghorithmName алгоритм подписи
     * @param data подписываемые данные
     * @param signature подпись
     * @return true - верна, false - не верна
     * @throws Exception /
     */
    public boolean verify(String alghorithmName,
                                 byte[] data, byte[] signature) throws Exception {
        return verify(alghorithmName, getPublicKey(STORE_PATH_2012_256, ALIAS_2012_256), data, signature);
    }

    /**
     * Пример генерирования запроса, отправки запроса центру сертификации и записи
     * полученного от центра сертификата в хранилище доверенных сертификатов
     *
     * @param keyAlg Алгоритм ключа.
     * @param signAlg Алгоритм подписи.
     * @param alias Алиас ключа для сохранения.
     * @param storePath Путь к хранилищу сертификатов.
     * @param dnName DN-имя сертификата.
     * @throws Exception /
     */
    private void writeCertSample(String keyAlg, String signAlg,
                                       String alias, String storePath, String dnName) throws Exception {
        /* Генерирование ключевой пары в соответствии с которой будет создан запрос
        на сертификат*/
        KeyPair keypair = keyPairGeneratorService.genKey(keyAlg);
        // отправка запроса центру сертификации и получение от центра
        // сертификата в DER-кодировке
        byte[] encoded = createRequestAndGetCert(keypair, signAlg, JCP.PROVIDER_NAME, dnName);

        // инициализация генератора X509-сертификатов
        CertificateFactory cf = CertificateFactory.getInstance(Constants.CF_ALG);
        // генерирование X509-сертификата из закодированного представления сертификата
        Certificate cert =
                cf.generateCertificate(new ByteArrayInputStream(encoded));

        /* Запись полученного от центра сертификата*/
        // инициализация хранилища доверенных сертификатов именем ключевого носителя
        // (жесткий диск)
        KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        // загрузка содержимого хранилища (предполагается, что инициализация
        // хранилища именем CertStoreName производится впервые, т.е. хранилища
        // с таким именем пока не существует)
        keyStore.load(null, null);

        //удаляем если уже существует
        if(keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
        }
        // запись сертификата в хранилище доверенных сертификатов
        // (предполагается, что на носителе с именем CertStoreName не существует
        // ключа с тем же именем alias)
        keyStore.setCertificateEntry(alias, cert);
        keyStore.setKeyEntry(alias, keypair.getPrivate(), STORE_PASS, new Certificate[]{cert});

        // определение пути к файлу для сохранения в него содержимого хранилища
        File file = new File(storePath);
        if (!file.exists()) {
            file.getParentFile().mkdirs();
        }
        // сохранение содержимого хранилища в файл
        keyStore.store(new FileOutputStream(file), STORE_PASS);
    }

    /**
     * Пример чтения сертификата из хранилища и записи его в файл
     *
     * @param storePath Путь к хранилищу сертификатов.
     * @param alias Алиас ключа подписи.
     * @throws Exception /
     */
    private Optional<Certificate> readCertSample(String storePath, String alias) throws Exception {
    /* Чтение сертификата их хранилища доверенных сертификатов */
        // инициализация хранилища доверенных сертификатов именем ключевого носителя
        // (жесткий диск)
        final KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        // определение пути к файлу для чтения содержимого хранилища
        // и последующего его сохранения
        final File file = new File(storePath);
        if (!file.exists()) {
            return Optional.empty();
        }
        // загрузка содержимого хранилища (предполагается, что хранилище,
        // проинициализированное именем CertStoreName существует)
        keyStore.load(new FileInputStream(file), STORE_PASS);

        // чтение сертификата из хранилища доверенных сертификатов
        // (предполагается, что на носителе с именем CertStoreName не существует
        // ключа с тем же именем alias)
        final Certificate cert = keyStore.getCertificate(alias);

        // сохранение содержимого хранилища в файл с тем же паролем
        keyStore.store(new FileOutputStream(file), STORE_PASS);
        return Optional.of(cert);
    }

    private PrivateKey getPrivateKey(String storePath, String alias) throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        final KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        final File file = new File(storePath);
        if (!file.exists()) {
           throw new FileNotFoundException("File " + STORE_TYPE + " not found while retrieving private key");
        }
        keyStore.load(new FileInputStream(file), STORE_PASS);
        return (PrivateKey) keyStore.getKey(alias, STORE_PASS);
    }

    private PublicKey getPublicKey(String storePath, String alias) throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        final KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        final File file = new File(storePath);
        if (!file.exists()) {
            throw new FileNotFoundException("File " + STORE_TYPE + " not found while retrieving public key");
        }
        keyStore.load(new FileInputStream(file), STORE_PASS);
        Certificate certificate = keyStore.getCertificate(alias);
        if (certificate == null) {
            throw new CertificateException("Certificate with alias " + alias + " not found while retrieving public key");
        }
        return certificate.getPublicKey();
    }

    /**
     * Функция формирует запрос на сертификат, отправляет запрос центру сертификации
     * и получает от центра сертификат.
     *
     * @param pair ключевая пара. Открытый ключ попадает в запрос на сертификат,
     * секретный ключ для подписи запроса.
     * @param signAlgorithm Алгоритм подписи.
     * @param signatureProvider Провайдер подписи.
     * @param dnName DN-имя сертификата.
     * @return сертификат в DER-кодировке
     * @throws Exception errors
     */
    private byte[] createRequestAndGetCert(KeyPair pair, String signAlgorithm,
                                                 String signatureProvider, String dnName) throws Exception {

        // формирование запроса
        GostCertificateRequest request = createRequest(pair,
                signAlgorithm, signatureProvider, dnName);

        // отправка запроса центру сертификации и получение от центра
        // сертификата в DER-кодировке
        return request.getEncodedCert(HTTP_ADDRESS);
    }

    /**
     * Функция формирует запрос на сертификат.
     *
     * @param pair ключевая пара. Открытый ключ попадает в запрос на сертификат,
     * секретный ключ для подписи запроса.
     * @param signAlgorithm Алгоритм подписи.
     * @param signatureProvider Провайдер подписи.
     * @param dnName DN-имя сертификата.
     * @return запрос
     * @throws Exception errors
     */
    private GostCertificateRequest createRequest(KeyPair pair, String signAlgorithm,
                                                       String signatureProvider, String dnName) throws Exception {
    /* Генерирование запроса на сертификат в соответствии с открытым ключом*/
        // создание генератора запроса на сертификат
        GostCertificateRequest request = new GostCertificateRequest(signatureProvider);
        // инициализация генератора
        // @deprecated с версии 1.0.48
        // вместо init() лучше использовать setKeyUsage() и addExtKeyUsage()
        // request.init(KEY_ALG);

    /*
    Установить keyUsage способ использования ключа можно функцией
    setKeyUsage. По умолчанию для ключа подписи, т.е. для указанного в первом
    параметре функции init() алгоритма "GOST3410EL" используется комбинация
    DIGITAL_SIGNATURE | NON_REPUDIATION. Для ключа шифрования, т.е. для
    алгоритма "GOST3410DHEL" добавляется KEY_ENCIPHERMENT | KEY_AGREEMENT.
    */
        final String keyAlgorithm = pair.getPrivate().getAlgorithm();
        if (keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_DEGREE_NAME) ||
                keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME) ||
                keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME)) {
            int keyUsage = GostCertificateRequest.DIGITAL_SIGNATURE |
                    GostCertificateRequest.NON_REPUDIATION;
            request.setKeyUsage(keyUsage);
        }
        else {
            int keyUsage = GostCertificateRequest.DIGITAL_SIGNATURE |
                    GostCertificateRequest.NON_REPUDIATION |
                    GostCertificateRequest.KEY_ENCIPHERMENT |
                    GostCertificateRequest.KEY_AGREEMENT;
            request.setKeyUsage(keyUsage);
        }

    /*
    Добавить ExtendedKeyUsage можно так. По умолчанию для ключа подписи,
    т.е. для алгоритма "GOST3410EL" список будет пустым. Для ключа
    шифрования, т.е. для алгоритма "GOST3410DHEL" добавляется OID
    INTS_PKIX_CLIENT_AUTH "1.3.6.1.5.5.7.3.2", а при установленном в true
    втором параметре функции init() еще добавляется INTS_PKIX_SERVER_AUTH
    "1.3.6.1.5.5.7.3.1"
    */
        request.addExtKeyUsage(GostCertificateRequest.INTS_PKIX_EMAIL_PROTECTION);

        // определение параметров и значения открытого ключа
        request.setPublicKeyInfo(pair.getPublic());
        // определение имени субъекта для создания запроса
        request.setSubjectInfo(dnName);
        // подпись сертификата на закрытом ключе и кодирование запроса
        request.encodeAndSign(pair.getPrivate(), signAlgorithm);

        return request;
    }

    private byte[] sign(String alghorithmName, PrivateKey privateKey,
                        byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature sign = Signature.getInstance(alghorithmName);
        sign.initSign(privateKey);
        sign.update(data);
        return sign.sign();
    }

    private boolean verify(String alghorithmName, PublicKey publicKey,
                           byte[] data, byte[] signature) throws Exception {
        final Signature sig = Signature.getInstance(alghorithmName);
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

}
