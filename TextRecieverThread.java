import java.net.*;
import CMPC3M06.AudioPlayer;
import java.nio.ByteBuffer;
import java.io.*;
import uk.ac.uea.cmp.voip.DatagramSocket2;
import uk.ac.uea.cmp.voip.DatagramSocket3;
import uk.ac.uea.cmp.voip.DatagramSocket4;


public class TextRecieverThread {
    
    static DatagramSocket4 receiving_socket;

    public static void main(String args[]) throws Exception {
        
        int PORT = 55557;
        try {
            receiving_socket = new DatagramSocket4(PORT);
        } catch (SocketException e) {
            System.out.println("ERROR: TextReceiver: Could not open UDP socket to receive from.");
            e.printStackTrace();
            System.exit(0);
        }

        AudioPlayer player = new AudioPlayer();
        int encryptkey = 15;
        short actualAuthKey = 10;

        boolean running = true;

        long startTime = System.currentTimeMillis();
        int packetCount = 0;
        int packetSize = 514; 

        while (running) {    
            try {
                byte[] buffer = new byte[packetSize];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket.receive(packet);

                long currentTime = System.currentTimeMillis();
                packetCount++;

                //BR FORMULA = PACKET SIZE X PACKET RECIEVED PER SEC / 1000
                if (currentTime - startTime >= 1000) { 
                    double bitrate = (packetSize * 8.0 * packetCount) / 1000; // kbps
                    System.out.println("Current Bitrate: " + bitrate + " kbps");

                    startTime = currentTime;
                    packetCount = 0;
                }

                ByteBuffer gottenKey = ByteBuffer.wrap(buffer, 0, 2);
                int authkey = gottenKey.getShort();

        

                if (authkey != actualAuthKey) {
                    // System.out.println("Invalid key, packet skipped");
                    continue;
                }

                int Length = packet.getLength() - 2;
                ByteBuffer unwrapDecrypt = ByteBuffer.allocate(Length);
                ByteBuffer cipherText = ByteBuffer.wrap(buffer, 2, Length);

                for (int j = 0; j < Length / 4; j++) {
                    int fourByte = cipherText.getInt();
                    fourByte = fourByte ^ encryptkey; 
                    unwrapDecrypt.putInt(fourByte);
                }

                byte[] decryptedBlock = unwrapDecrypt.array();
                player.playBlock(decryptedBlock);

            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver: Some random IO error occurred!");
                e.printStackTrace();
            }
        }

        receiving_socket.close();
    }
}
