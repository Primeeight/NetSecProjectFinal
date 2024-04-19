import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Client {
    private static PrivateKey clientPrivateKey;
    private static PublicKey serverPublicKey;

    public static void main(String[] args) throws Exception {
        // Initializations
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        Socket socket = new Socket("localhost", 12345);
        System.out.println("Connected to server.");

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String serverPublicKeyBase64 = in.readLine();
        System.out.println("Received server's ECC public key: " + serverPublicKeyBase64);

        byte[] publicKeyBytes = Base64.getDecoder().decode(serverPublicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        serverPublicKey = keyFactory.generatePublic(keySpec);

        // Get and print the keys
        KeyPair clientKeyPair = ECCUtilities.generateECCKeyPair();
        clientPrivateKey = clientKeyPair.getPrivate();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        System.out.println("Client Public Key: " + bytesToBase64(clientPublicKey.getEncoded()));
        System.out.println("Client Private Key: " + bytesToBase64(clientPrivateKey.getEncoded()));

        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        String clientPublicKeyBase64 = bytesToBase64(clientPublicKey.getEncoded());
        out.println(clientPublicKeyBase64);

        // Thread for reading messages from the server
        Thread readThread = new Thread(() -> {
            try {
                while (true) {
                    String encryptedMessage = in.readLine();
                    if (encryptedMessage == null) {
                        System.out.println("Server closed the connection.");
                        break;
                    }

                    String decryptedMessage = ECCUtilities.decryptECC(encryptedMessage, clientPrivateKey);
                    System.out.println("Decrypted message from server: " + decryptedMessage);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        readThread.start();

        BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            String message = userInput.readLine();
            try {
                String encryptedMessage = ECCUtilities.encryptECC(message, serverPublicKey);
                out.println(encryptedMessage);
            } catch (Exception e) {
                System.err.println("Error encrypting message: " + e.getMessage());
            }
        }
    }

    private static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
