import java.net.*;
import CMPC3M06.AudioPlayer;
import java.nio.ByteBuffer;
import java.io.*;
import uk.ac.uea.cmp.voip.DatagramSocket2;
import uk.ac.uea.cmp.voip.DatagramSocket3;
import uk.ac.uea.cmp.voip.DatagramSocket4;


public class TextRecieverThread {
    
    static DatagramSocket2 receiving_socket;

    public static void main(String args[]) throws Exception {
        
        int PORT = 55557;
        try {
            receiving_socket = new DatagramSocket2(PORT);
        } catch (SocketException e) {
            System.out.println("ERROR: TextReceiver: Could not open UDP socket to receive from.");
            e.printStackTrace();
            System.exit(0);
        }

        AudioPlayer player = new AudioPlayer();
        int encryptkey = 15;
        short actualAuthKey = 10;

        boolean running = true;

        long lastIntervalTime = System.currentTimeMillis();
        int packets = 0;
        int packetSize = 514; 

        while (running) {    
            try {
                byte[] buffer = new byte[packetSize];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket.receive(packet);

                
                long currentTime = System.currentTimeMillis();
                packets++;
                
                double totalBitrate = 0;
                int count = 0;
                
                // = packet size * how many per sec / 1000 (for kps)
                //basically  when wehita second in elapsed time do this
                if (currentTime - lastIntervalTime >= 1000) { 
                    double bitrate = (packetSize * 8 * packets) / 1000; 
                    totalBitrate += bitrate;
                    count++;
                    double avgBitrate = totalBitrate / count;
                    System.out.println("Average Bitrate: " + avgBitrate + " kbps");
                    lastIntervalTime = currentTime;
                    packets = 0;
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
