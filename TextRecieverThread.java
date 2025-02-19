/*
 * TextReceiver.java
 */

/**
 *
 * @author  abj
 */
import java.net.*;
import CMPC3M06.AudioPlayer;
import java.nio.ByteBuffer;
import java.io.*;

public class TextReceiverThread{
    
    static DatagramSocket receiving_socket;
    
    public static void main(String args[])throws Exception{
     
        //***************************************************
        //Port to open socket on
        int PORT = 55557;
        //***************************************************
        
        //***************************************************
        //Open a socket to receive from on port PORT
        
        //DatagramSocket receiving_socket;
        try{
		receiving_socket = new DatagramSocket(PORT);
	} catch (SocketException e){
                System.out.println("ERROR: TextReceiver: Could not open UDP socket to receive from.");
		e.printStackTrace();
                System.exit(0);
	}
        //***************************************************
        
        //***************************************************
        //Main loop.
        
        AudioPlayer player = new AudioPlayer();

        int key = 15;

        boolean running = true;
        while (running){    
            try {
                byte[] buffer = new byte[512];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket.receive(packet);

                ByteBuffer unwrapDecrypt = ByteBuffer.allocate(buffer.length);

                ByteBuffer cipherText = ByteBuffer.wrap(buffer);
                for(int j = 0; j < buffer.length/4; j++) {
                    int fourByte = cipherText.getInt();
                    fourByte = fourByte ^ key; 
                    unwrapDecrypt.putInt(fourByte);
                }

                byte[] decryptedBlock = unwrapDecrypt.array();
                player.playBlock(decryptedBlock);

                
            } catch (IOException e){
                System.out.println("ERROR: TextSender: Some random IO error occured!");
                e.printStackTrace();
            }
        
        }


        //Close the socket
        receiving_socket.close();
        //***************************************************
    }
}
