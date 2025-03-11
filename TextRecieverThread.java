import CMPC3M06.AudioPlayer;
import java.nio.ByteBuffer;
import java.io.*;
import java.net.*;
import java.util.*;

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
        // socketWithDecrypt();
        // socketWithoutDecrypt();
        // socket2();
        // socket3();
        socket4();

    }

    public static class PacketInfo {
        int sequenceNum;
        byte[] block;
    
        PacketInfo(int sequenceNum, byte[] block) {
            this.sequenceNum = sequenceNum;
            this.block = block;
        }
    }
    

    //xor our data with our key, then take thencreate a 32byte array of data consisting of every other bytes first bit.
    private static byte[] generateSimpleMAC(byte[] data, int key) {
        byte[] xored = new byte[512];
    
        for (int i = 0; i < 512; i++) {
            xored[i] = (byte) (data[i] ^ key);
        }
        byte[] mac = new byte[32];
        int bitIndex = 0;
    
        for (int i = 0; i < 512; i += 2) {
            int bit = (xored[i] >> 7) & 1; 
            mac[bitIndex / 8] |= (bit << (7 - (bitIndex % 8))); 
            bitIndex++;
            if (bitIndex == 256) break; 
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

                byte[] sendermac = new byte[32];
                ByteBuffer macBuffer = ByteBuffer.wrap(alldata.array(), 514, 32);
                macBuffer.get(sendermac);

                byte[] reciver = generateSimpleMAC(audioData, sharedSecret.intValue());
                if (!Arrays.equals(sendermac, reciver)) {
                    System.out.println("No auth");
                    player.playBlock(lastAudio);
                    continue;
                }

                byte[] decryptedBlock = DecryptData(audioData, key,newKey);
                player.playBlock(decryptedBlock);
                lastAudio = decryptedBlock;

                
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

                byte[] sendermac = new byte[32];
                ByteBuffer macBuffer = ByteBuffer.wrap(alldata.array(), 514, 32);
                macBuffer.get(sendermac);

                
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
        receiving_socket2 = new DatagramSocket2(PORT);
    
        AudioPlayer player = new AudioPlayer();
        int encryptkey = 15;
    
        PriorityQueue<PacketInfo> jitterBuffer = new PriorityQueue<>(
            (a, b) -> Integer.compare(a.sequenceNum, b.sequenceNum)
        );
    
        HashSet<Integer> receivedSequenceNumbers = new HashSet<>();
        int preSeqNum = -1;
        int highestSeqNum = 0;
        int jitterBufferSize = 3;
        int max =0;
        int count = 0;
    
        while (highestSeqNum < 1000) {
            try {
                byte[] buffer = new byte[516];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket2.receive(packet);

    
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
    
            
                if (jitterBuffer.size() >= jitterBufferSize) {
                    PacketInfo earliestPacket = jitterBuffer.peek();
                    if (earliestPacket.sequenceNum <= highestSeqNum - jitterBufferSize + 1) {
                        PacketInfo toPlay = jitterBuffer.poll();
                        player.playBlock(toPlay.block);
                        lastAudio = toPlay.block;
                        preSeqNum = toPlay.sequenceNum;
                    }
                }
    
                while (!jitterBuffer.isEmpty() && jitterBuffer.peek().sequenceNum > preSeqNum + 3) {
                    
                    System.out.println("Packet loss so playing last audio.");
                    if (lastAudio != null && max<2) {
                        max++;
                        player.playBlock(lastAudio);
                    }
                    else{max=0;}
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
    
            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver encountered an issue!");
                e.printStackTrace();
            }
        }
    
        receiving_socket2.close();
        // System.out.println("Received packets: " + receivedSequenceNumbers.size());
        // System.out.println(receivedSequenceNumbers);
    }
    

    public static void socket3() throws Exception {
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
        int jitterBufferSize = 6; 
        int packets = 0;
        boolean running = true;
        int count = 0;
        byte[] lastAudio = null;
    
        while (running) {
            try {
                byte[] buffer = new byte[516];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket3.receive(packet);
    
                ByteBuffer headerBuffer = ByteBuffer.wrap(buffer, 0, 4);
                int sequenceNum = headerBuffer.getShort();
                if (receivedSequenceNumbers.contains(sequenceNum)) {
                    continue;
                }
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
    
                receivedSequenceNumbers.add(sequenceNum);
                highestSeqNum = Math.max(highestSeqNum, sequenceNum);
    
                jitterBuffer.offer(new PacketInfo(sequenceNum, decryptedBlock));
    
                if (jitterBuffer.size() >= jitterBufferSize) {
                    PacketInfo earliestPacket = jitterBuffer.peek();
                    if (earliestPacket.sequenceNum <= highestSeqNum - jitterBufferSize + 1) {
                        PacketInfo toPlay = jitterBuffer.poll();
                        player.playBlock(toPlay.block);
                        lastAudio = toPlay.block;
                        preSeqNum = toPlay.sequenceNum;
                        packets++;
                    }
                }
    
                while (!jitterBuffer.isEmpty() && jitterBuffer.peek().sequenceNum > preSeqNum + 3) {
                    System.out.println("Packet loss so playing last audio.");
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
                    packets++;
                }
    
            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver encountered an issue!");
                e.printStackTrace();
            }
        }
    
        receiving_socket3.close();
    }


    public static void socket4() throws Exception {
        int PORT = 55557;
        receiving_socket4 = new DatagramSocket4(PORT);
        InetAddress clientIP = InetAddress.getByName("localhost");

       
        Random random = new Random();
        privateKey = BigInteger.valueOf(random.nextInt(21) + 1);
        publicKey = SmallNum.modPow(privateKey, Prime);
        System.out.println("Receiver Private Key: " + privateKey);
        System.out.println("Receiver Public Key: " + publicKey);

        byte[] received = new byte[4];
        DatagramPacket receiverKeyPacket = new DatagramPacket(received, received.length);
        receiving_socket4.receive(receiverKeyPacket);  

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
        receiving_socket4.send(finalKeyPacket);
        System.out.println("Receiver sent Public Key: " + publicKey.intValue());


        int key = sharedSecret.intValue();
        int nextadd = (int)(Math.log(key) / Math.log(2));
        int rawNewKey = (nextadd + 1) * key * (key * key - (4 * key) - 1);
        int newKey = Math.abs(rawNewKey) % 65536; 

        
        AudioPlayer player = new AudioPlayer();
        int highestSeqNum = 0;

        while (highestSeqNum < 1000) {
            try {
                byte[] buffer = new byte[548];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiving_socket4.receive(packet);
                

                ByteBuffer alldata = ByteBuffer.wrap(buffer, 0, 546);
                ByteBuffer packetData = ByteBuffer.wrap(alldata.array(), 0, 514);
                int sequenceNum = packetData.getShort();

                byte[] audioData = new byte[512];
                ByteBuffer audioBuffer = ByteBuffer.wrap(alldata.array(), 2, 512);
                audioBuffer.get(audioData);

                byte[] sendermac = new byte[32];
                ByteBuffer macBuffer = ByteBuffer.wrap(alldata.array(), 514, 32);
                macBuffer.get(sendermac);



                byte[] reciver = generateSimpleMAC(audioData, sharedSecret.intValue());
                if (!Arrays.equals(sendermac, reciver)) {
                    System.out.println("No auth");
                    if(lastAudio!=null)player.playBlock(lastAudio);
                    continue;
                }

                byte[] decryptedData = DecryptData(audioData, key, newKey);

                player.playBlock(decryptedData);

                
            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver encountered an issue!");
                e.printStackTrace();
            }
        }
        receiving_socket4.close();
    }
}
