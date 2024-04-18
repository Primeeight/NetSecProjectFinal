import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class server {
    private static List<ClientHandler> clients = new ArrayList<>();
    static Map<ClientHandler, PublicKey> clientPublicKeys = new HashMap<>();
    private static PublicKey serverPublicKey;
    private static PrivateKey serverPrivateKey;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPair serverKeyPair = ECCKeyGenerator.generateECCKeyPair();
        serverPublicKey = serverKeyPair.getPublic();
        serverPrivateKey = serverKeyPair.getPrivate();

        System.out.println("Server started. Using public key: " + bytesToBase64(serverPublicKey.getEncoded()));

        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server started. Waiting for clients...");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket);

            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            String serverPublicKeyBase64 = bytesToBase64(serverPublicKey.getEncoded());
            out.println(serverPublicKeyBase64);

            ClientHandler clientHandler = new ClientHandler(clientSocket, serverPrivateKey);  // Pass clientPrivateKey to constructor
            clients.add(clientHandler);
            clientHandler.start();
        }
    }

    public static void broadcastMessage(String message) {
        for (ClientHandler clientHandler : clients) {
            try {
                String encryptedMessage = encryptECC(message, clientPublicKeys.get(clientHandler));
                System.out.println("Sending message to: " + clientHandler.getClientAddress() + " - " + encryptedMessage);
                clientHandler.sendMessage(encryptedMessage);
            } catch (Exception e) {
                System.err.println("Error encrypting message for client: " + e.getMessage());
            }
        }
    }

    public static String encryptECC(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptECC(String encryptedText, PrivateKey privateKey) throws Exception {  // Added privateKey parameter
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    private static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
