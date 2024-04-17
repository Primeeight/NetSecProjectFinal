import java.io.*;
import java.net.*;

public class client {
    private static boolean hasChosenName = false;

    public static void main(String[] args) throws Exception {
        // Connect to the server
        Socket socket = new Socket("localhost", 12345);
        System.out.println("Connected to server.");

        BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        // Thread for reading messages from the server
        Thread readThread = new Thread(() -> {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    if (!hasChosenName) {
                        System.out.println(inputLine);
                        System.out.print("Animal Choice: ");
                        hasChosenName = true;
                    } else {
                        System.out.println(inputLine);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        readThread.start();

        // Thread for sending messages to the server
        while (true) {
            String message = userInput.readLine();
            out.println(message);
        }
    }
}
