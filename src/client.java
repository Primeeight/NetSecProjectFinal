import java.io.*;
import java.net.*;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class client {

    public static void main(String[] args) throws Exception {
        // Explicitly register Bouncy Castle provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Connect to the server
        Socket socket = new Socket("localhost", 12345);
        System.out.println("Connected to server.");

        // Generate ECC key pair
        KeyPair keyPair = generateECCKeyPair();
        PublicKey clientPublicKey = keyPair.getPublic();
        PrivateKey clientPrivateKey = keyPair.getPrivate();

        // Send ECC public key to the server
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        String publicKeyBase64 = bytesToBase64(clientPublicKey.getEncoded());
        out.println(publicKeyBase64);

        // Thread for reading messages from the server
        Thread readThread = new Thread(() -> {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    String decryptedMessage = decryptECC(inputLine, clientPrivateKey);
                    System.out.println("Received decrypted message from server: " + decryptedMessage);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        readThread.start();

        // Thread for sending messages to the server
        BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            String message = userInput.readLine();
            try {
                String encryptedMessage = encryptECC(message, clientPublicKey);
                out.println(encryptedMessage);
            } catch (Exception e) {
                System.err.println("Error encrypting message: " + e.getMessage());
            }
        }
    }

    private static KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(256); // 256-bit key size
        return keyGen.generateKeyPair();
    }

    private static String encryptECC(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptECC(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    private static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
