import java.net.*;
import java.nio.ByteBuffer;
import java.io.*;
import CMPC3M06.AudioRecorder;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import uk.ac.uea.cmp.voip.DatagramSocket4;
import uk.ac.uea.cmp.voip.DatagramSocket2;
import uk.ac.uea.cmp.voip.DatagramSocket3;
import java.math.BigInteger;
import java.security.SecureRandom;


public class TextSenderThread {
    static DatagramSocket sending_socket;
    static DatagramSocket2 sending_socket2;
    static DatagramSocket3 sending_socket3;
    static DatagramSocket4 sending_socket4;

    private static final BigInteger Prime = BigInteger.valueOf(23);
    private static final BigInteger SmallNum = BigInteger.valueOf(5);
    static BigInteger privateKey;
    static BigInteger publicKey;
    static BigInteger sharedSecret;

    
    public static void main(String args[]) throws Exception {
        socket();
        // socket2();
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
    


    //transposition, xor, transposition2, xor2, byteshift
    private static byte[] EncryptData(byte[] audioData, int key,int  other_key) throws Exception {
    
        byte[] transposedAudio1 = new byte[512];
        byte[] transposedAudioPlusXOR1 = new byte[512];
        byte[] transposedAudio2 = new byte[512];
        byte[] transposedAudioPlusXOR2 = new byte[512];
        byte[] finalAudio = new byte[512];
    
    
        int index = 0;
        int rows = 64, columns = 8;
        for (int i = 0; i < columns; i++) {
            for (int j = 0; j < rows; j++) {
                int newIndex = (j * columns) + i;
                transposedAudio1[index++] = audioData[newIndex];
            }
        }
    
        for (int i = 0; i < 512; i++) {
            transposedAudioPlusXOR1[i] = (byte) (transposedAudio1[i] ^ key);
        }
    
        index = 0;
        rows = 128;
        columns = 4;
        for (int i = 0; i < columns; i++) {
            for (int j = 0; j < rows; j++) {
                int newIndex = (j * columns) + i;
                transposedAudio2[index++] = transposedAudioPlusXOR1[newIndex];
            }
        }
    
        for (int i = 0; i < 512; i++) {
            transposedAudioPlusXOR2[i] = (byte) (transposedAudio2[i] ^ other_key);
        }
    
        for (int i = 0; i < 512; i++) {
            int newIndex = (i + key) % 512;
            finalAudio[newIndex] = transposedAudioPlusXOR2[i];
            }
    
        return finalAudio;
    }


    public static void socket() throws Exception {
        int PORT = 55557;            
        InetAddress clientIP = InetAddress.getByName("localhost");
        try {
            sending_socket = new DatagramSocket();
        } catch (SocketException e) {
            System.out.println("ERROR: TextSender: Could not open UDP socket to send from.");
            e.printStackTrace();
            System.exit(0);
        }

       
        SecureRandom random = new SecureRandom();
        privateKey = new BigInteger(5, random).add(BigInteger.ONE); 
        publicKey = SmallNum.modPow(privateKey, Prime);
        System.out.println("Sender Private Key: " + privateKey);
        System.out.println("Sender Public Key: " + publicKey);

        ByteBuffer keyPacket = ByteBuffer.allocate(4);
        keyPacket.putInt(publicKey.intValue());
        byte[] shared = keyPacket.array();
        DatagramPacket finalKeyPacket = new DatagramPacket(shared, shared.length, clientIP, PORT);
        sending_socket.send(finalKeyPacket);
        System.out.println("Sender sent Public Key: " + publicKey.intValue());

        byte[] received = new byte[4];
        DatagramPacket receiverKeyPacket = new DatagramPacket(received, received.length);
        sending_socket.receive(receiverKeyPacket);  

        if (receiverKeyPacket.getAddress().equals(InetAddress.getLocalHost()) &&
            receiverKeyPacket.getPort() == sending_socket.getLocalPort()) {
            System.out.println("sender received own");
            return;
        }
        
        ByteBuffer pubKeyBuffer = ByteBuffer.wrap(received);
        BigInteger receivedPublicKey = BigInteger.valueOf(pubKeyBuffer.getInt());
        System.out.println("Sender received Public Key: " + receivedPublicKey);

        sharedSecret = receivedPublicKey.modPow(privateKey, Prime);
        System.out.println("Sender Shared Secret: " + sharedSecret);
        
        AudioRecorder recorder = new AudioRecorder();
        boolean running = true;
        short packetSequenceNum = 0;
        
        int key = sharedSecret.intValue();
        int nextadd = (int)(Math.log(key) / Math.log(2));
        int rawNewKey = (nextadd + 1) * key * (key * key - (4 * key) - 1);
        int newKey = Math.abs(rawNewKey) % 65536; 
    
        while (running) {
            try {
                byte[] block1 = recorder.getBlock();
                byte[] audio1 = new byte[512];
                System.arraycopy(block1, 0, audio1, 0, 512);

                ByteBuffer packetBuffer1 = ByteBuffer.allocate(514); 
                packetSequenceNum++;
                packetBuffer1.putShort(packetSequenceNum);


                byte[] encryptedAudioData = EncryptData(audio1, key, newKey);
                byte[] secretBytes = ByteBuffer.allocate(4).putInt(key).array();
                byte[] hmac = generateSimpleMAC(encryptedAudioData, secretBytes); 

                ByteBuffer finalPacketBuffer = ByteBuffer.allocate(514 + hmac.length); 
                finalPacketBuffer.putShort(packetSequenceNum);         
                finalPacketBuffer.put(encryptedAudioData);  
                finalPacketBuffer.put(hmac);  

                byte[] finalPacketData = finalPacketBuffer.array();  

                DatagramPacket finalPacket = new DatagramPacket(finalPacketData, finalPacketData.length, clientIP, PORT);
                sending_socket.send(finalPacket);

                System.out.println("sent");
                
            } catch (IOException e) {
                System.out.println("ERROR: TextSender: Some random IO error occurred!");
                e.printStackTrace();
            }
        }
        sending_socket.close();
    }




    public static void socket2() throws Exception {
        int PORT = 55557;
        InetAddress clientIP = InetAddress.getByName("localhost");
        
        try {
            sending_socket3 = new DatagramSocket3();
        } catch (SocketException e) {
            System.out.println("ERROR: TextSender: Could not open UDP socket to send from.");
            e.printStackTrace();
            System.exit(0);
        }
    
        AudioRecorder recorder = new AudioRecorder();
        boolean running = true;
    
        short encryptkey = 15;
        short authKey = 10;
        short packetSequenceNum = 0;
    

        while (running) {
            try {
                byte[] block1 = recorder.getBlock();  
                byte[] block2 = recorder.getBlock(); 
                byte[] block3 = recorder.getBlock();  
                byte[] block4 = recorder.getBlock(); 

                
                ByteBuffer packetBuffer1 = ByteBuffer.allocate(516);
                packetSequenceNum++;
                short seqNum1 = packetSequenceNum;
                packetBuffer1.putShort(seqNum1);
                packetBuffer1.putShort(authKey);
                ByteBuffer plainText1 = ByteBuffer.wrap(block1);
                for (int j = 0; j < block1.length / 4; j++) {
                    int fourByte = plainText1.getInt();
                    fourByte = fourByte ^ encryptkey;
                    packetBuffer1.putInt(fourByte);
                }
                byte[] encryptedBlock1 = packetBuffer1.array();
                DatagramPacket packet1 = new DatagramPacket(encryptedBlock1, encryptedBlock1.length, clientIP, PORT);

                sending_socket3.send(packet1);  // Packet 1
                sending_socket3.send(packet1);  // Packet 1
                // sending_socket3.send(packet1);  // Packet 1


                // Packet 2
                ByteBuffer packetBuffer2 = ByteBuffer.allocate(516);
                packetSequenceNum++;
                short seqNum2 = packetSequenceNum;
                packetBuffer2.putShort(seqNum2);
                packetBuffer2.putShort(authKey);
                ByteBuffer plainText2 = ByteBuffer.wrap(block2);
                for (int j = 0; j < block2.length / 4; j++) {
                    int fourByte = plainText2.getInt();
                    fourByte = fourByte ^ encryptkey;
                    packetBuffer2.putInt(fourByte);
                }
                byte[] encryptedBlock2 = packetBuffer2.array();
                DatagramPacket packet2 = new DatagramPacket(encryptedBlock2, encryptedBlock2.length, clientIP, PORT);
                sending_socket3.send(packet2);  // Packet 2
                sending_socket3.send(packet2);  // Packet 2
                // sending_socket3.send(packet2);  // Packet 2

                // Packet 3
                ByteBuffer packetBuffer3 = ByteBuffer.allocate(516);
                packetSequenceNum++;
                short seqNum3 = packetSequenceNum;
                packetBuffer3.putShort(seqNum3);
                packetBuffer3.putShort(authKey);
                ByteBuffer plainText3 = ByteBuffer.wrap(block3);
                for (int j = 0; j < block3.length / 4; j++) {
                    int fourByte = plainText3.getInt();
                    fourByte = fourByte ^ encryptkey;
                    packetBuffer3.putInt(fourByte);
                }
                byte[] encryptedBlock3 = packetBuffer3.array();
                DatagramPacket packet3 = new DatagramPacket(encryptedBlock3, encryptedBlock3.length, clientIP, PORT);
                sending_socket3.send(packet3);  // Packet 3
                sending_socket3.send(packet3);  // Packet 3
                // sending_socket3.send(packet3);  // Packet 3


                // Packet 4
                ByteBuffer packetBuffer4 = ByteBuffer.allocate(516);
                packetSequenceNum++;
                short seqNum4 = packetSequenceNum;
                packetBuffer4.putShort(seqNum4);
                packetBuffer4.putShort(authKey);
                ByteBuffer plainText4 = ByteBuffer.wrap(block4);
                for (int j = 0; j < block4.length / 4; j++) {
                    int fourByte = plainText4.getInt();
                    fourByte = fourByte ^ encryptkey;
                    packetBuffer4.putInt(fourByte);
                }
                byte[] encryptedBlock4 = packetBuffer4.array();
                DatagramPacket packet4 = new DatagramPacket(encryptedBlock4, encryptedBlock4.length, clientIP, PORT);

                sending_socket3.send(packet4);  // Packet 4
                sending_socket3.send(packet4);  // Packet 4
                // sending_socket3.send(packet4);  // Packet 4


                
    } catch (Exception e) {
        e.printStackTrace();
    }
}
}



public static void socket3() throws Exception {
    int PORT = 55557;            
    InetAddress clientIP = InetAddress.getByName("localhost");
    try {
        sending_socket3 = new DatagramSocket3();
    } catch (SocketException e) {
        System.out.println("ERROR: TextSender: Could not open UDP socket to send from.");
        e.printStackTrace();
        System.exit(0);
    }


    AudioRecorder recorder = new AudioRecorder();
    boolean running = true;
    int encryptkey = 2;
    short authkey = 12;
    short packetSequenceNum = 0;
    
    while (packetSequenceNum < 1000) {
        try {
            byte[] block1 = recorder.getBlock();
            byte[] audio1 = new byte[512];
            System.arraycopy(block1, 0, audio1, 0, 512);

            ByteBuffer packetBuffer1 = ByteBuffer.allocate(516); 
            packetSequenceNum++;
            packetBuffer1.putShort(authkey);
            packetBuffer1.putShort(packetSequenceNum);


            ByteBuffer plainText1 = ByteBuffer.wrap(audio1);
                for (int j = 0; j < audio1.length / 4; j++) {
                    int fourByte = plainText1.getInt();
                    fourByte = fourByte ^ encryptkey;
                    packetBuffer1.putInt(fourByte);
                }
            byte[] encryptedBlock1 = packetBuffer1.array();
              

            DatagramPacket finalPacket = new DatagramPacket(encryptedBlock1, encryptedBlock1.length, clientIP, PORT);
            sending_socket3.send(finalPacket);
            


            // System.out.println("sent");
            
        } catch (IOException e) {
            System.out.println("ERROR: TextSender: Some random IO error occurred!");
            e.printStackTrace();
        }
    }
    sending_socket3.close();
    System.out.println("Packets sent: "+ packetSequenceNum);
    

    }
}