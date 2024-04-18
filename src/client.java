import java.io.*;
import java.net.*;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class client {

    private static PrivateKey clientPrivateKey; // Store the client's private key
    private static PublicKey serverPublicKey; // Store the server's public key

    public static void main(String[] args) throws Exception {
        // Explicitly register Bouncy Castle provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Connect to the server
        System.out.println("Connecting to server...");
        Socket socket = new Socket("localhost", 12345);
        System.out.println("Connected to server.");

        // Receive ECC public key from the server
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        System.out.println("Waiting for server's ECC public key...");
        String serverPublicKeyBase64 = in.readLine();
        System.out.println("Received server's ECC public key: " + serverPublicKeyBase64);

        byte[] publicKeyBytes = Base64.getDecoder().decode(serverPublicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        serverPublicKey = keyFactory.generatePublic(keySpec);

        // Generate ECC key pair for the client
        System.out.println("Generating client's ECC key pair...");
        KeyPair clientKeyPair = ECCKeyGenerator.generateECCKeyPair();
        clientPrivateKey = clientKeyPair.getPrivate();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        System.out.println("Generated client's ECC key pair:");
        System.out.println("Client Public Key: " + bytesToBase64(clientPublicKey.getEncoded()));
        System.out.println("Client Private Key: " + bytesToBase64(clientPrivateKey.getEncoded()));

        // Send client's ECC public key to the server
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        String clientPublicKeyBase64 = bytesToBase64(clientPublicKey.getEncoded());
        System.out.println("Sending client's ECC public key to server...");
        out.println(clientPublicKeyBase64);
        System.out.println("Sent client's ECC public key to server.");

        // Thread for reading messages from the server
        Thread readThread = new Thread(() -> {
            try {
                while (true) {
                    System.out.println("Waiting for encrypted message from server...");
                    String encryptedMessage = in.readLine();
                    if (encryptedMessage == null) {
                        System.out.println("Server closed the connection.");
                        break;
                    }
                    String decryptedMessage = decryptECC(encryptedMessage, clientPrivateKey);  // Use client's private key for decryption
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
            System.out.println("Enter message to send to server:");
            String message = userInput.readLine();
            try {
                String encryptedMessage = encryptECC(message, serverPublicKey);
                System.out.println("Sending encrypted message to server...");
                out.println(encryptedMessage);
                System.out.println("Sent encrypted message to server.");
            } catch (Exception e) {
                System.err.println("Error encrypting message: " + e.getMessage());
            }
        }
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
