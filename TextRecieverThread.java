import CMPC3M06.AudioPlayer;
import java.nio.ByteBuffer;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;
import java.util.concurrent.TimeoutException;

import uk.ac.uea.cmp.voip.DatagramSocket2;
import uk.ac.uea.cmp.voip.DatagramSocket3;
import uk.ac.uea.cmp.voip.DatagramSocket4;

import java.math.BigInteger;


public class TextRecieverThread {
    static DatagramSocket receiving_socket;
    static DatagramSocket2 receiving_socket2;
    static DatagramSocket3 receiving_socket3;
    static DatagramSocket4 receiving_socket4;

    static final BigInteger Prime = BigInteger.valueOf(23);
    static final BigInteger SmallNum= BigInteger.valueOf(5);
    static BigInteger privateKey;
    static BigInteger publicKey;
    static BigInteger sharedSecret;

    static byte[] lastAudio;
    static int count = 0;
    static HashSet<Integer> receivedSequenceNumbers = new HashSet<>();
    static long lastTimeChecked = System.currentTimeMillis();
    static int packetCount = 0;


    public static void main(String args[]) throws Exception {
        socketWithDecrypt();
        // socket2();

    }

    public static class PacketInfo {
        int sequenceNum;
        byte[] block;
    
        PacketInfo(int sequenceNum, byte[] block) {
            this.sequenceNum = sequenceNum;
            this.block = block;
        }
    }
    


    private static byte[] generateSimpleMAC(byte[] data, byte[] key) {
        if (data.length != 512) {
            throw new IllegalArgumentException("Data must be exactly 512 bytes.");
        }
    
        byte[] xored = new byte[512];
    
        // XOR each byte of data with the key (cycling if key is shorter)
        for (int i = 0; i < 512; i++) {
            xored[i] = (byte) (data[i] ^ key[i % key.length]);
        }
    
        byte[] mac = new byte[32];
        int bitIndex = 0;
    
        // Extract first bit of every other byte
        for (int i = 0; i < 512; i += 2) {
            int bit = (xored[i] >> 7) & 1; // Get MSB (first bit)
            mac[bitIndex / 8] |= (bit << (7 - (bitIndex % 8))); // Pack bits into bytes
            bitIndex++;
            if (bitIndex == 256) break; // Stop after 256 bits (32 bytes)
        }
    
        return mac;
    }


    //byte shift, xor, transposition, xor2, transposition2
    private static byte[] DecryptData(byte[] encryptedAudioData, int key,int other_key) throws Exception {  
    
        byte[] shifted = new byte[512];
        byte[] transposedAudioXOR2 = new byte[512];
        byte[] transposedAudio2 = new byte[512];
        byte[] transposedAudioXOR = new byte[512];
        byte[] original = new byte[512];
    

    
        for (int i = 0; i < 512; i++) {
            int newIndex = ((i - key + 512) % 512); 
            shifted[newIndex] = encryptedAudioData[i];
        }
    
        for (int i = 0; i < shifted.length; i++) {
            transposedAudioXOR2[i] = (byte) (shifted[i] ^ other_key);
        }
    
        int index = 0;
        int rows = 128, columns = 4;
        for (int i = 0; i < columns; i++) {
            for (int j = 0; j < rows; j++) {
                int newIndex = (j * columns) + i;
                transposedAudio2[newIndex] = transposedAudioXOR2[index++];
            }
        }
    
        for (int i = 0; i < transposedAudio2.length; i++) {
            transposedAudioXOR[i] = (byte) (transposedAudio2[i] ^ key);
        }
    
        index = 0;
        rows = 64;
        columns = 8;
        for (int i = 0; i < columns; i++) {
            for (int j = 0; j < rows; j++) {
                int newIndex = (j * columns) + i;
                original[newIndex] = transposedAudioXOR[index++];
            }
        }
    
        return original;
    }
    


    public static void socketWithDecrypt() throws Exception {
        int PORT = 55557;
        receiving_socket = new DatagramSocket(PORT);
        InetAddress clientIP = InetAddress.getByName("localhost");

       
        Random random = new Random();
        privateKey = BigInteger.valueOf(random.nextInt(21) + 1);
        publicKey = SmallNum.modPow(privateKey, Prime);
        System.out.println("Receiver Private Key: " + privateKey);
        System.out.println("Receiver Public Key: " + publicKey);

        byte[] received = new byte[4];
        DatagramPacket receiverKeyPacket = new DatagramPacket(received, received.length);
        receiving_socket.receive(receiverKeyPacket);  

        ByteBuffer pubKeyBuffer = ByteBuffer.wrap(received);
        int receivedPublicKeyInt = pubKeyBuffer.getInt();
        BigInteger receivedPublicKey = BigInteger.valueOf(receivedPublicKeyInt);
        System.out.println("Receiver received Public Key: " + receivedPublicKey);

        sharedSecret = receivedPublicKey.modPow(privateKey, Prime);
        System.out.println("reciever shared Secret: " + sharedSecret);


        ByteBuffer keyPacket = ByteBuffer.allocate(4);
        keyPacket.putInt(publicKey.intValue());
        byte[] shared = keyPacket.array();

        DatagramPacket finalKeyPacket = new DatagramPacket(shared, shared.length, receiverKeyPacket.getAddress(), receiverKeyPacket.getPort());
        receiving_socket.send(finalKeyPacket);
        System.out.println("Receiver sent Public Key: " + publicKey.intValue());


        byte[] secretBytes = ByteBuffer.allocate(4).putInt(sharedSecret.intValue()).array();

        AudioPlayer player = new AudioPlayer();
        int highestSeqNum = 0;

        int key = sharedSecret.intValue();
        int nextadd = (int)(Math.log(key) / Math.log(2));
        int rawNewKey = (nextadd + 1) * key * (key * key - (4 * key) - 1);
        int newKey = Math.abs(rawNewKey) % 65536; 

        while (highestSeqNum < 1000) {
            try {
                byte[] buffer = new byte[548];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket.receive(packet);
                

                ByteBuffer alldata = ByteBuffer.wrap(buffer, 0, 546);
                ByteBuffer packetData = ByteBuffer.wrap(alldata.array(), 0, 514);
                int sequenceNum = packetData.getShort();

                byte[] audioData = new byte[512];
                ByteBuffer audioBuffer = ByteBuffer.wrap(alldata.array(), 2, 512);
                audioBuffer.get(audioData);

                byte[] senderhash = new byte[32];
                ByteBuffer hmacBuffer = ByteBuffer.wrap(alldata.array(), 514, 32);
                hmacBuffer.get(senderhash);

                byte[] reciverhash = generateSimpleMAC(audioData, secretBytes);
                if (!Arrays.equals(senderhash, reciverhash)) {
                    System.out.println("No auth");
                }

                byte[] decryptedBlock = DecryptData(audioData, key,newKey);
                player.playBlock(decryptedBlock);

                
            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver encountered an issue!");
                e.printStackTrace();
            }
        }
        receiving_socket.close();
    }


    public static void socketWithoutDecrypt() throws Exception {
        int PORT = 55557;
        receiving_socket = new DatagramSocket(PORT);
        InetAddress clientIP = InetAddress.getByName("localhost");

       
        Random random = new Random();
        privateKey = BigInteger.valueOf(random.nextInt(21) + 1);
        publicKey = SmallNum.modPow(privateKey, Prime);
        System.out.println("Receiver Private Key: " + privateKey);
        System.out.println("Receiver Public Key: " + publicKey);

        byte[] received = new byte[4];
        DatagramPacket receiverKeyPacket = new DatagramPacket(received, received.length);
        receiving_socket.receive(receiverKeyPacket);  

        ByteBuffer pubKeyBuffer = ByteBuffer.wrap(received);
        int receivedPublicKeyInt = pubKeyBuffer.getInt();
        BigInteger receivedPublicKey = BigInteger.valueOf(receivedPublicKeyInt);
        System.out.println("Receiver received Public Key: " + receivedPublicKey);

        sharedSecret = receivedPublicKey.modPow(privateKey, Prime);
        System.out.println("reciever shared Secret: " + sharedSecret);


        ByteBuffer keyPacket = ByteBuffer.allocate(4);
        keyPacket.putInt(publicKey.intValue());
        byte[] shared = keyPacket.array();

        DatagramPacket finalKeyPacket = new DatagramPacket(shared, shared.length, receiverKeyPacket.getAddress(), receiverKeyPacket.getPort());
        receiving_socket.send(finalKeyPacket);
        System.out.println("Receiver sent Public Key: " + publicKey.intValue());


        byte[] secretBytes = ByteBuffer.allocate(4).putInt(sharedSecret.intValue()).array();

        AudioPlayer player = new AudioPlayer();
        int encryptkey = 15;
        int highestSeqNum = 0;

        while (highestSeqNum < 1000) {
            try {
                byte[] buffer = new byte[548];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket.receive(packet);
                

                ByteBuffer alldata = ByteBuffer.wrap(buffer, 0, 546);
                ByteBuffer packetData = ByteBuffer.wrap(alldata.array(), 0, 514);
                int sequenceNum = packetData.getShort();

                byte[] audioData = new byte[512];
                ByteBuffer audioBuffer = ByteBuffer.wrap(alldata.array(), 2, 512);
                audioBuffer.get(audioData);

                byte[] senderhash = new byte[32];
                ByteBuffer hmacBuffer = ByteBuffer.wrap(alldata.array(), 514, 32);
                hmacBuffer.get(senderhash);

                // byte[] reciverhash = generateSimpleMAC(audioData, secretBytes);
                // if (!Arrays.equals(senderhash, reciverhash)) {
                //     System.out.println("No auth");
                // }

                player.playBlock(audioData);

                
            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver encountered an issue!");
                e.printStackTrace();
            }
        }
        receiving_socket.close();
    }



    public static void socket2() throws Exception {
        int PORT = 55557;
        receiving_socket3 = new DatagramSocket3(PORT);
    
        AudioPlayer player = new AudioPlayer();
        int encryptkey = 15;
    
        PriorityQueue<PacketInfo> jitterBuffer = new PriorityQueue<>(
            (a, b) -> Integer.compare(a.sequenceNum, b.sequenceNum)
        );
    
        HashSet<Integer> receivedSequenceNumbers = new HashSet<>();
        int preSeqNum = -1;
        int highestSeqNum = 0;
        int jitterBufferSize = 1;
    
        int count = 0;
    
        while (highestSeqNum < 1000) {
            try {
                byte[] buffer = new byte[516];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket3.receive(packet);

    
                ByteBuffer headerBuffer = ByteBuffer.wrap(buffer, 0, 4);
                int sequenceNum = headerBuffer.getShort();
                short authKey = headerBuffer.getShort();
    
                int total = packet.getLength() - 4;
                ByteBuffer cipherText = ByteBuffer.wrap(buffer, 4, total);
                ByteBuffer unwrapDecrypt = ByteBuffer.allocate(total);
                for (int j = 0; j < total / 4; j++) {
                    int fourByte = cipherText.getInt();
                    fourByte = fourByte ^ encryptkey;
                    unwrapDecrypt.putInt(fourByte);
                }
                byte[] decryptedBlock = unwrapDecrypt.array();
    
                if (receivedSequenceNumbers.contains(sequenceNum)) {
                    continue;
                }
                receivedSequenceNumbers.add(sequenceNum);
                highestSeqNum = Math.max(highestSeqNum, sequenceNum);
    
                jitterBuffer.offer(new PacketInfo(sequenceNum, decryptedBlock));
    
            
                while (!jitterBuffer.isEmpty() && jitterBuffer.peek().sequenceNum > preSeqNum + 3) {
                    System.out.println("Packet loss burst detected. Playing last audio.");
                    if (lastAudio != null) {
                        player.playBlock(lastAudio);
                    }
                    preSeqNum++; 
                    count++;
                }
    
                while (!jitterBuffer.isEmpty() && jitterBuffer.peek().sequenceNum == preSeqNum + 1) {
                    PacketInfo entry = jitterBuffer.poll();
                    byte[] audioBlock = entry.block;
                    player.playBlock(audioBlock);
                    lastAudio = audioBlock;
                    preSeqNum = entry.sequenceNum;
                }
    
               
                if (jitterBuffer.size() > jitterBufferSize) {
                    while (jitterBuffer.size() > 1) {
                        jitterBuffer.poll();
                    }
                    PacketInfo latest = jitterBuffer.poll();
                    player.playBlock(latest.block);
                    lastAudio = latest.block;
                    preSeqNum = latest.sequenceNum;
                }
    
            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver encountered an issue!");
                e.printStackTrace();
            }
        }
    
        receiving_socket3.close();
        System.out.println("Timeout/Fill count: " + count);
        System.out.println("Received packets: " + receivedSequenceNumbers.size());
        System.out.println(receivedSequenceNumbers);
    }
    



public static void socket3() throws Exception {
    int PORT = 55557;
    receiving_socket3 = new DatagramSocket3(PORT);
    InetAddress clientIP = InetAddress.getByName("localhost");

    boolean running = true;
    AudioPlayer player = new AudioPlayer();
    int encryptkey = 2;
    int authkey = 12;
    int highestSeqNum = 0;
    int packetsRecieved = 0;
    ArrayList<Short> totalPacketNums = new ArrayList<>();

    receiving_socket3.setSoTimeout(5000);
    while (running = true) {
        try {
            byte[] buffer = new byte[516]; 
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try{
                receiving_socket3.receive(packet);
            }catch(SocketTimeoutException e){
                break;
            }

            System.out.println(packet.getLength());
            ByteBuffer headerBuffer = ByteBuffer.wrap(buffer, 0, 4);
            short authKey = headerBuffer.getShort();
            short sequenceNum = headerBuffer.getShort();
            totalPacketNums.add(sequenceNum);
            


            highestSeqNum =sequenceNum;
            int total = packet.getLength() - 4;
            ByteBuffer cipherText = ByteBuffer.wrap(buffer, 4, total);
            ByteBuffer unwrapDecrypt = ByteBuffer.allocate(total);
            for (int j = 0; j < total / 4; j++) {
                int fourByte = cipherText.getInt();
                fourByte = fourByte ^ encryptkey; 
                unwrapDecrypt.putInt(fourByte);
            }
            byte[] decryptedBlock = unwrapDecrypt.array();


           
            player.playBlock(decryptedBlock);

            packetsRecieved++;

            
        } catch (IOException e) {
            System.out.println("ERROR: TextReceiver encountered an issue!");
            e.printStackTrace();
        }
    }


    receiving_socket3.close();

    System.out.println("Packets recieevd: "+ packetsRecieved);
    System.out.println("highest Packets recieevd: "+ highestSeqNum);
    System.out.println(totalPacketNums);


}
}