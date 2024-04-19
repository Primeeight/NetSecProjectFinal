import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class Server {
    // Initializations
    private static List<ClientHandler> clients = new ArrayList<>();
    static Map<ClientHandler, PublicKey> clientPublicKeys = new HashMap<>();
    private static PublicKey serverPublicKey;
    private static PrivateKey serverPrivateKey;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPair serverKeyPair = ECCUtilities.generateECCKeyPair();
        serverPublicKey = serverKeyPair.getPublic();
        serverPrivateKey = serverKeyPair.getPrivate();

        System.out.println("Server started.\n Server is using private key: " + bytesToBase64(serverPrivateKey.getEncoded()));
        System.out.println("Server is using public key: " + bytesToBase64(serverPublicKey.getEncoded()));

        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server started. Waiting for clients...");

        // Upon successful client connection
        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket);

            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            String serverPublicKeyBase64 = bytesToBase64(serverPublicKey.getEncoded());
            out.println(serverPublicKeyBase64);

            ClientHandler clientHandler = new ClientHandler(clientSocket, serverPrivateKey);
            clients.add(clientHandler);
            clientHandler.start();
        }
    }

    //Return encryption for each maintained connection
    public static void broadcastMessage(String message) {
        for (ClientHandler clientHandler : clients) {
            try {
                String encryptedMessage = ECCUtilities.encryptECC(message, clientPublicKeys.get(clientHandler));
                System.out.println("Sending message to: " + clientHandler.getClientAddress() + " - " + encryptedMessage);
                clientHandler.sendMessage(encryptedMessage);
            } catch (Exception e) {
                System.err.println("Error encrypting message for client: " + e.getMessage());
            }
        }
    }

    private static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
