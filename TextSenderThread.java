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
import uk.ac.uea.cmp.voip.DatagramSocket2;
import uk.ac.uea.cmp.voip.DatagramSocket3;
import uk.ac.uea.cmp.voip.DatagramSocket4;


public class TextSenderThread {
    
    static DatagramSocket sending_socket;

    
    public static void main(String args[]) throws Exception{
    
      
        int PORT = 55557;
        InetAddress clientIP = null;
	try {
		clientIP = InetAddress.getByName("localhost");  //CHANGE localhost to IP or NAME of client machine
	} catch (UnknownHostException e) {
                System.out.println("ERROR: TextSender: Could not find client IP");
		e.printStackTrace();
                System.exit(0);
	}
   
        try{
		sending_socket = new DatagramSocket();
	} catch (SocketException e){
                System.out.println("ERROR: TextSender: Could not open UDP socket to send from.");
		e.printStackTrace();
                System.exit(0);
	}
    
        AudioRecorder recorder = new AudioRecorder();

        boolean running = true;

        short encryptkey = 15;
        short authKey = 10;
        short packetSequenceNum = 0;

        //packet layout - sequence num, authkey, security key, data
        while (running){    
            try {
                packetSequenceNum += 1;
                byte[] buffer = recorder.getBlock();
                ByteBuffer unwrapEncrypt = ByteBuffer.allocate(516);

                unwrapEncrypt.putShort(packetSequenceNum);

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
                System.out.println("Sent packet " + packetSequenceNum);
                                
                sending_socket.setSoTimeout(100);
                
                try {
                    byte[] ackData = new byte[2]; 
                    DatagramPacket ackPacket = new DatagramPacket(ackData, ackData.length);
                    System.out.println("Waiting for ACK for packet " + packetSequenceNum);
                    sending_socket.receive(ackPacket);  

                    ByteBuffer ackBuffer = ByteBuffer.wrap(ackData);
                    short receivedSeqNum = ackBuffer.getShort();
                    System.out.println("received ACK for packet: " + receivedSeqNum);       
                } catch (SocketTimeoutException e) {
                    System.out.println("No acl received for packet " + packetSequenceNum);
                }
                
            } catch (IOException e){
                System.out.println("ERROR: TextSender: Some random IO error occurred!");
                e.printStackTrace();
            }
        
        }
        sending_socket.close();
        //***************************************************
    }


} 
