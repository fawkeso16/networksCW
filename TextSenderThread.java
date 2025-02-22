/*
 * TextSender.java
 */

/**
 *
 * @author  abj
 */
import java.net.*;
import java.nio.ByteBuffer;
import java.io.*;
import CMPC3M06.AudioRecorder;

public class TextSenderThread {
    
    static DatagramSocket sending_socket;
    
    
    public static void main(String args[]) throws Exception{
    
        //***************************************************
        //Port to send to
        int PORT = 55557;
        //IP ADDRESS to send to
        InetAddress clientIP = null;
	try {
		clientIP = InetAddress.getByName("localhost");  //CHANGE localhost to IP or NAME of client machine
	} catch (UnknownHostException e) {
                System.out.println("ERROR: TextSender: Could not find client IP");
		e.printStackTrace();
                System.exit(0);
	}
        //***************************************************
        
        //***************************************************
        //Open a socket to send from
        //We dont need to know its port number as we never send anything to it.
        //We need the try and catch block to make sure no errors occur.
        
        //DatagramSocket sending_socket;
        try{
		sending_socket = new DatagramSocket();
	} catch (SocketException e){
                System.out.println("ERROR: TextSender: Could not open UDP socket to send from.");
		e.printStackTrace();
                System.exit(0);
	}
        //***************************************************
      
        //***************************************************
        //Get a handle to the Standard Input (console) so we can read user input
        
        // BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        //***************************************************
        
        //***************************************************
        //Main loop.
        
     
        AudioRecorder recorder = new AudioRecorder();

        boolean running = true;

        int encryptkey = 15;
        short authKey = 10;

        while (running){    
            try {
                byte[] buffer = recorder.getBlock();
                ByteBuffer unwrapEncrypt = ByteBuffer.allocate(514);

                //add 2 bit auth key
                unwrapEncrypt.putShort(authKey);
                ByteBuffer plainText = ByteBuffer.wrap(buffer);
                
                for(int j = 0; j < buffer.length/4; j++){
                    int fourByte = plainText.getInt();
                    fourByte = fourByte ^ encryptkey;
                    unwrapEncrypt.putInt(fourByte);
                }

                byte[] encryptedBlock = unwrapEncrypt.array();
                DatagramPacket packet = new DatagramPacket(encryptedBlock, encryptedBlock.length, clientIP, PORT);
                sending_socket.send(packet);

                
            } catch (IOException e){
                System.out.println("ERROR: TextSender: Some random IO error occured!");
                e.printStackTrace();
            }
        
        }
        //Close the socket
        sending_socket.close();
        //***************************************************
    }
} 
