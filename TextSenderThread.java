import java.net.*;
import java.nio.ByteBuffer;
import java.io.*;
import CMPC3M06.AudioRecorder;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;


import uk.ac.uea.cmp.voip.DatagramSocket2;
import uk.ac.uea.cmp.voip.DatagramSocket3;
import java.math.BigInteger;
import java.security.SecureRandom;


public class TextSenderThread {
    static DatagramSocket sending_socket;
    static DatagramSocket2 sending_socket2;
    static DatagramSocket3 sending_socket3;
    static DatagramSocket3 sending_socket4;

    private static final BigInteger Prime = BigInteger.valueOf(23);
    private static final BigInteger SmallNum = BigInteger.valueOf(5);
    static BigInteger privateKey;
    static BigInteger publicKey;
    static BigInteger sharedSecret;

    private static byte[] generateHMAC(byte[] data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(data);
    }

    public static void main(String args[]) throws Exception {
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

        // Thread.sleep(500);
    
        byte[] received = new byte[4];
        DatagramPacket receiverKeyPacket = new DatagramPacket(received, received.length);
        sending_socket.receive(receiverKeyPacket);

        ByteBuffer pubKeyBuffer = ByteBuffer.wrap(received);
        BigInteger receivedPublicKey = BigInteger.valueOf(pubKeyBuffer.getInt());
        System.out.println("Sender received Public Key: " + receivedPublicKey);
    
        sharedSecret = receivedPublicKey.modPow(privateKey, Prime);
        System.out.println("Sender Shared Secret: " + sharedSecret);

        AudioRecorder recorder = new AudioRecorder();
        boolean running = true;
        short encryptkey = 15;
        short packetSequenceNum = 0;
    
        while (running) {
            try {
                byte[] block1 = recorder.getBlock();
                byte[] audio1 = new byte[512];
                System.arraycopy(block1, 0, audio1, 0, 512);

                ByteBuffer packetBuffer1 = ByteBuffer.allocate(514); 
                packetSequenceNum++;
                packetBuffer1.putShort(packetSequenceNum);

                ByteBuffer plainText1 = ByteBuffer.wrap(audio1);
                ByteBuffer encryptedDataBuffer = ByteBuffer.allocate(audio1.length); 

                for (int j = 0; j < audio1.length / 4; j++) {
                    int fourByte = plainText1.getInt();
                    fourByte = fourByte ^ encryptkey; 
                    encryptedDataBuffer.putInt(fourByte);
                }

                byte[] encryptedAudioData = encryptedDataBuffer.array();  

                byte[] secretBytes = ByteBuffer.allocate(4).putInt(sharedSecret.intValue()).array();
                byte[] hmac = generateHMAC(encryptedAudioData, secretBytes); 

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




    public static void socket2(String args[]) throws Exception {
        int PORT = 55557;
        InetAddress clientIP = InetAddress.getByName("localhost");
        
        try {
            sending_socket2 = new DatagramSocket2();
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
    
                byte[] audio1 = new byte[1024];
                System.arraycopy(block1, 0, audio1, 0, 512);
                System.arraycopy(block2, 0, audio1, 512, 512);
    
                byte[] audio2 = new byte[1024];
                System.arraycopy(block3, 0, audio2, 0, 512);
                System.arraycopy(block4, 0, audio2, 512, 512);
    
                ByteBuffer packetBuffer1 = ByteBuffer.allocate(1028); 
                packetSequenceNum++;
                packetBuffer1.putShort(packetSequenceNum);
                packetBuffer1.putShort(authKey);
                ByteBuffer plainText1 = ByteBuffer.wrap(audio1);
                for (int j = 0; j < audio1.length / 4; j++) {
                    int fourByte = plainText1.getInt();
                    fourByte = fourByte ^ encryptkey;
                    packetBuffer1.putInt(fourByte);
                }
                byte[] encryptedBlock1 = packetBuffer1.array();
                DatagramPacket packet1 = new DatagramPacket(encryptedBlock1, encryptedBlock1.length, clientIP, PORT);
                sending_socket2.send(packet1);
                sending_socket2.send(packet1); 
                sending_socket2.send(packet1); 

    
                ByteBuffer packetBuffer2 = ByteBuffer.allocate(1028);
                packetSequenceNum++;
                packetBuffer2.putShort(packetSequenceNum);
                packetBuffer2.putShort(authKey);
                ByteBuffer plainText2 = ByteBuffer.wrap(audio2);
                for (int j = 0; j < audio2.length / 4; j++) {
                    int fourByte = plainText2.getInt();
                    fourByte = fourByte ^ encryptkey;
                    packetBuffer2.putInt(fourByte);
                }
                byte[] encryptedBlock2 = packetBuffer2.array();
                DatagramPacket packet2 = new DatagramPacket(encryptedBlock2, encryptedBlock2.length, clientIP, PORT);
                sending_socket2.send(packet2);
                sending_socket2.send(packet2); 
                sending_socket2.send(packet2); 

    
            } catch (IOException e) {
                System.out.println("ERROR: TextSender: Some random IO error occurred!");
                e.printStackTrace();
            }
        }
        sending_socket2.close();
    }
}