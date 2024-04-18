import java.io.*;
import java.net.*;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class client {
    private static PrivateKey clientPrivateKey;
    private static PublicKey serverPublicKey;

    public static void main(String[] args) throws Exception {
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

        KeyPair clientKeyPair = ECCKeyGenerator.generateECCKeyPair();
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

                    String decryptedMessage = decryptECC(encryptedMessage, clientPrivateKey);
                    System.out.println("Decrypted message from server: " + decryptedMessage);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        readThread.start();

        BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.println("Enter message to send to server:");
            String message = userInput.readLine();
            try {
                String encryptedMessage = encryptECC(message, serverPublicKey);
                out.println(encryptedMessage);
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
