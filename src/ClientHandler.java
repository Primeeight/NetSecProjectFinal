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
    private PublicKey clientPublicKey; // Store the client's public key
    private PrivateKey serverPrivateKey; // Store the server's private key

    public ClientHandler(Socket socket, PrivateKey serverPrivateKey) {
        this.clientSocket = socket;
        this.serverPrivateKey = serverPrivateKey;
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

            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            while (true) {
                System.out.println("Waiting for encrypted message from client...");
                String encryptedMessage = in.readLine();
                if (encryptedMessage == null) {
                    System.out.println("Client closed the connection.");
                    break;
                }
                String decryptedMessage = decryptECC(encryptedMessage, serverPrivateKey); // Use server's private key for decryption
                System.out.println("Received decrypted message from client: " + decryptedMessage);

                System.out.println("Enter message to send back to client:");
                String message = userInput.readLine();
                try {
                    String encryptedReply = encryptECC(message, clientPublicKey);
                    System.out.println("Sending encrypted reply to client...");
                    out.println(encryptedReply);
                    System.out.println("Sent encrypted reply to client.");
                } catch (Exception e) {
                    System.err.println("Error encrypting reply: " + e.getMessage());
                }
            }

            in.close();
            out.close();
            clientSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String encryptECC(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decryptECC(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}
