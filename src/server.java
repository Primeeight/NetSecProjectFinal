import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class server {
    private static List<ClientHandler> clients = new ArrayList<>();
    private static PublicKey serverPublicKey; // Store the server's public key

    public static void main(String[] args) throws Exception {
        // Explicitly register Bouncy Castle provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Generate ECC key pair for the server
        System.out.println("Generating server's ECC key pair...");
        KeyPair serverKeyPair = ECCKeyGenerator.generateECCKeyPair();
        PublicKey serverPublicKey = serverKeyPair.getPublic();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        System.out.println("Generated server's ECC key pair:");
        System.out.println("Server Public Key: " + bytesToBase64(serverPublicKey.getEncoded()));
        System.out.println("Server Private Key: " + bytesToBase64(serverPrivateKey.getEncoded()));

        // Start the server
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server started. Waiting for clients...");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket);

            // Send server's ECC public key to the client
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            String serverPublicKeyBase64 = bytesToBase64(serverPublicKey.getEncoded());
            System.out.println("Sending server's ECC public key to client...");
            out.println(serverPublicKeyBase64);
            System.out.println("Sent server's ECC public key to client.");

            ClientHandler clientHandler = new ClientHandler(clientSocket, serverPrivateKey);
            clients.add(clientHandler);
            clientHandler.start();
        }
    }

    private static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static void broadcastMessage(String message) {
        System.out.println("Broadcasting message: " + message);
        for (ClientHandler clientHandler : clients) {
            clientHandler.sendMessage(message);
        }
    }

    public static void removeClient(ClientHandler clientHandler) {
        clients.remove(clientHandler);
        System.out.println("Client disconnected. Total clients: " + clients.size());
    }
}
