package cryptopro.jcp.example;

import ru.CryptoPro.JCP.JCP;

public class Constants {

    /* Алгоритмы */

    /**
     * алгоритм ключа подписи: "GOST3410EL" или JCP.GOST_EL_DEGREE_NAME
     */
    public static final String SIGN_KEY_PAIR_ALG_2001 = JCP.GOST_EL_DEGREE_NAME;
    /**
     * алгоритм ключа подписи: "GOST3410_2012_256" или JCP.GOST_EL_2012_256_NAME
     */
    public static final String SIGN_KEY_PAIR_ALG_2012_256 = JCP.GOST_EL_2012_256_NAME;
    /**
     * алгоритм ключа подписи: "GOST3410_2012_512" или JCP.GOST_EL_2012_512_NAME
     */
    public static final String SIGN_KEY_PAIR_ALG_2012_512 = JCP.GOST_EL_2012_512_NAME;
    /**
     * стандарт сертификата "X509" или JCP.CERTIFICATE_FACTORY_NAME
     */
    public static final String CF_ALG = "X509";
    /**
     * алгоритм подписи ГОСТ Р 34.10-2001: "GOST3411withGOST3410EL" или
     * JCP.GOST_EL_SIGN_NAME
     */
    public static final String SIGN_EL_ALG_2001 = JCP.GOST_EL_SIGN_NAME;
    /**
     * алгоритм подписи ГОСТ Р 34.10-2012 (256): "GOST3411_2012_256withGOST3410_2012_256" или
     * JCP.GOST_SIGN_2012_256_NAME
     */
    public static final String SIGN_EL_ALG_2012_256 = JCP.GOST_SIGN_2012_256_NAME;
    /**
     * алгоритм подписи ГОСТ Р 34.10-2012 (512): "GOST3411_2012_512withGOST3410_2012_512" или
     * JCP.GOST_SIGN_2012_512_NAME
     */
    public static final String SIGN_EL_ALG_2012_512 = JCP.GOST_SIGN_2012_512_NAME;
    /**
     * алгоритм подписи ГОСТ Р 34.10-2001 (используется для совеместимости с
     * криптопровайдером CryptoPro CSP): "CryptoProSignature" или
     * JCP.CRYPTOPRO_SIGN_NAME
     */
    public static final String SIGN_CP_ALG_2001 = JCP.CRYPTOPRO_SIGN_NAME;
    /**
     * алгоритм подписи ГОСТ Р 34.10-2012 (256) (используется для совеместимости с
     * криптопровайдером CryptoPro CSP): "CryptoProSignature_2012_256" или
     * JCP.CRYPTOPRO_SIGN_2012_256_NAME
     */
    public static final String SIGN_CP_ALG_2012_256 = JCP.CRYPTOPRO_SIGN_2012_256_NAME;
    /**
     * алгоритм подписи ГОСТ Р 34.10-2012 (512) (используется для совеместимости с
     * криптопровайдером CryptoPro CSP): "CryptoProSignature_2012_512" или
     * JCP.CRYPTOPRO_SIGN_2012_512_NAME
     */
    public static final String SIGN_CP_ALG_2012_512 = JCP.CRYPTOPRO_SIGN_2012_512_NAME;

    /**
     * тип хранилища:
     * <p/>
     * "HDImageStore" - жесткий диск
     * <p/>
     * "FloppyStore" - дискета, флешка
     * <p/>
     * "OCFStore" или "J6CFStore" - карточка
     */
    public static final String KEYSTORE_TYPE = JCP.HD_STORE_NAME;

    /**
     * hex-string
     *
     * @param array массив данных
     * @return hex-string
     */
    public static String toHexString(byte[] array) {
        final char[] hex = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
                'B', 'C', 'D', 'E', 'F'};
        StringBuffer ss = new StringBuffer(array.length * 3);
        for (int i = 0; i < array.length; i++) {
            ss.append(' ');
            ss.append(hex[(array[i] >>> 4) & 0xf]);
            ss.append(hex[array[i] & 0xf]);
        }
        return ss.toString();
    }
}

