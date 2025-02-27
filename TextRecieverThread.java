import java.net.*;
import CMPC3M06.AudioPlayer;
import java.nio.ByteBuffer;
import java.io.*;
import uk.ac.uea.cmp.voip.DatagramSocket2;

public class TextRecieverThread {
    
    static DatagramSocket receiving_socket;

    public static void main(String args[]) throws Exception {
        
        int PORT = 55557;
        receiving_socket = new DatagramSocket(PORT);
        
        AudioPlayer player = new AudioPlayer();
        int encryptkey = 15;
        short actualAuthKey = 10;
        short prevSeqNum = 0;

        boolean running = true;
        while (running) {    
            try {
                byte[] buffer = new byte[516]; 
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket.receive(packet);

                ByteBuffer packetNum = ByteBuffer.wrap(buffer, 0, 2);
                short sequenceNum = packetNum.getShort();

                ByteBuffer authKeyBuf = ByteBuffer.wrap(buffer, 2, 2);
                short authKey = authKeyBuf.getShort();
                if (authKey != actualAuthKey) continue; 

                if (prevSeqNum != -1 && sequenceNum != prevSeqNum + 1) {
                    System.out.println("Packet Loss - Expected " + (prevSeqNum + 1) + " but received " + sequenceNum);
                }

                int length = packet.getLength() - 4;
                ByteBuffer unwrapDecrypt = ByteBuffer.allocate(length);
                ByteBuffer cipherText = ByteBuffer.wrap(buffer, 4, length);

                for (int j = 0; j < length / 4; j++) {
                    int fourByte = cipherText.getInt();
                    fourByte = fourByte ^ encryptkey; 
                    unwrapDecrypt.putInt(fourByte);
                }

                byte[] decryptedBlock = unwrapDecrypt.array();
                player.playBlock(decryptedBlock);

                ByteBuffer ackBuffer = ByteBuffer.allocate(2);
                ackBuffer.putShort(sequenceNum); 
                byte[] ackData = ackBuffer.array();
                DatagramPacket ackPacket = new DatagramPacket(ackData, ackData.length, packet.getAddress(), packet.getPort());
                receiving_socket.send(ackPacket);
                System.out.println("ACK sent for packet " + sequenceNum);

                prevSeqNum = sequenceNum;

            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver: Some random IO error occurred!");
                e.printStackTrace();
            }
        }

        receiving_socket.close();
    }
}
