import javax.crypto.Cipher;
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
    private PrivateKey clientPrivateKey;  // Instance variable to store client's private key

    public ClientHandler(Socket socket, PrivateKey clientPrivateKey) {  // Modify the constructor to accept clientPrivateKey
        this.clientSocket = socket;
        this.clientPrivateKey = clientPrivateKey;  // Store clientPrivateKey
        try {
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            String publicKeyBase64 = in.readLine();
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            clientPublicKey = keyFactory.generatePublic(keySpec);

            // Update clientPublicKeys map
            Server.clientPublicKeys.put(this, clientPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendMessage(String message) {
        out.println(message);
    }

    public String getClientAddress() {
        return clientSocket.getRemoteSocketAddress().toString();
    }

    public void run() {
        try {
            while (true) {
                String encryptedMessage = in.readLine();
                if (encryptedMessage == null) {
                    break;
                }

                System.out.println("Encrypted message from client: " + encryptedMessage);

                String decryptedMessage = ECCUtilities.decryptECC(encryptedMessage, clientPrivateKey);  // Use client's private key for decryption
                System.out.println("Decrypted message: " + decryptedMessage);

                // Broadcast the decrypted message directly
                Server.broadcastMessage(decryptedMessage);
            }

            in.close();
            out.close();
            clientSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
