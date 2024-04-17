import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.List;

public class server {
    private static List<ClientHandler> clients = new ArrayList<>();

    public static void main(String[] args) throws Exception {
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

    public static void broadcastMessage(String message) {
        System.out.println("Broadcasting message: " + message);
        for (ClientHandler clientHandler : clients) {
            if (clientHandler.isReady()) {
                clientHandler.sendMessage(message);
            }
        }
    }
}
