import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class server {
    private static List<ClientHandler> clients = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        // Explicitly register Bouncy Castle provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server started. Waiting for clients...");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket);

            ClientHandler clientHandler = new ClientHandler(clientSocket);
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
