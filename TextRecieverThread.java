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
import uk.ac.uea.cmp.voip.DatagramSocket2;
import uk.ac.uea.cmp.voip.DatagramSocket3;
import uk.ac.uea.cmp.voip.DatagramSocket4;

public class TextRecieverThread{
    
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
        int encryptkey = 15;
        short actualAuthKey = 10;

        boolean running = true;
        while (running){    
            try {
                byte[] buffer = new byte[514];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket.receive(packet);

                ByteBuffer gottenKey = ByteBuffer.wrap(buffer,0,2);
                int authkey = gottenKey.getShort();
                System.out.println("Received key: " + authkey);

                if(authkey == actualAuthKey){
                    System.out.println("valid key");
                } else {
                    System.out.println("Invalid key, packet skipped");
                    continue;
                }

                int Length = packet.getLength() - 2;
                ByteBuffer unwrapDecrypt = ByteBuffer.allocate(Length);
                //start from end of auth key
                ByteBuffer cipherText = ByteBuffer.wrap(buffer, 2, Length);

                for(int j = 0; j < Length/4; j++) {
                    int fourByte = cipherText.getInt();
                    fourByte = fourByte ^ encryptkey; 
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
