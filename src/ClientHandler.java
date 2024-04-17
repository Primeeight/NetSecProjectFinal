import java.io.*;
import java.net.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

public class ClientHandler extends Thread {
    private Socket clientSocket;
    private PrintWriter out;
    private String animalName;
    private boolean ready = false;
    private DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    public void sendMessage(String message) {
        out.println(message);
    }

    public boolean isReady() {
        return ready;
    }

    @Override
    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);

            // Prompt the client to choose an animal name
            if (animalName == null) {
                out.println("Please choose an animal name (e.g., Rabbit, Duck, Pig):");
                animalName = in.readLine();
                System.out.println("Client " + animalName + " connected.");
                ready = true;
                server.broadcastMessage("Client " + animalName + " connected.");
            }

            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                if (ready && !inputLine.startsWith(animalName + ": ")) {
                    LocalTime currentTime = LocalTime.now();
                    String formattedTime = currentTime.format(timeFormatter);
                    String response = "[" + formattedTime + " " + animalName + "]: " + inputLine;
                    server.broadcastMessage(response);
                }
            }

            // Broadcast when client disconnects
            if (ready) {
                System.out.println("Client " + animalName + " disconnected.");
                server.broadcastMessage("Client " + animalName + " disconnected.");
            }

            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
