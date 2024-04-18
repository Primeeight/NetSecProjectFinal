import java.security.*;

public class ECCKeyGenerator {

    public static KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(256); // 256-bit key size
        return keyGen.generateKeyPair();
    }
}
