import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ClientHandler extends Thread {
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private PublicKey clientPublicKey;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    public void sendMessage(String message) {
        out.println(message);
    }

    @Override
    public void run() {
        try {
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            System.out.println("Waiting for client's ECC public key...");
            String publicKeyBase64 = in.readLine();
            System.out.println("Received client's ECC public key: " + publicKeyBase64);

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            clientPublicKey = keyFactory.generatePublic(keySpec);

            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                System.out.println("Received encrypted message from client: " + inputLine);
                server.broadcastMessage(inputLine); // Broadcast the encrypted message to all clients
            }

            // Broadcast when client disconnects
            System.out.println("Client disconnected.");
            server.removeClient(this);

            in.close();
            out.close();
            clientSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}