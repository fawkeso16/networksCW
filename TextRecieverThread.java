import CMPC3M06.AudioPlayer;
import java.nio.ByteBuffer;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;
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

    }


    private static byte[] generateHMAC(byte[] data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(data);
    }


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

                byte[] reciverhash = generateHMAC(audioData, secretBytes);
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

                byte[] reciverhash = generateHMAC(audioData, secretBytes);
                if (!Arrays.equals(senderhash, reciverhash)) {
                    System.out.println("No auth");
                }

                player.playBlock(audioData);

                
            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver encountered an issue!");
                e.printStackTrace();
            }
        }
        receiving_socket.close();
    }



    public static void socket2(String args[]) throws Exception {
        int PORT = 55557;
        receiving_socket2 = new DatagramSocket2(PORT);
        
        AudioPlayer player = new AudioPlayer();
        int encryptkey = 15;
        short actualAuthKey = 10;

        HashMap<Integer, byte[]> audioHolder = new HashMap<>();
        int preSeqNum = -1;
        int highestSeqNum = 0; 
        int expectedSeqNumber = 0;

        while (highestSeqNum < 1000) {    
            try {
                byte[] buffer = new byte[1028]; 
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

                if (sequenceNum > expectedSeqNumber) {
                    System.out.println("Packet loss  expected " + expectedSeqNumber+" but got " + sequenceNum );
                    if (lastAudio != null) {
                        player.playBlock(lastAudio);
                        count += 1;
                    }
                }


                expectedSeqNumber = sequenceNum + 1;
                if (audioHolder.containsKey(sequenceNum)) {
                    continue;
                }
                receivedSequenceNumbers.add(sequenceNum);
                highestSeqNum = Math.max(highestSeqNum, sequenceNum);

                //Here we check if the packet we have is odd,if so then we check if we have the even counterpart,
                //if we do we get it, then un ravel and play inorder. if not we just play the odd on its own.
                boolean isOdd = (sequenceNum % 2) == 1;
                audioHolder.put(sequenceNum, decryptedBlock);
                int matchingNum;
                if (isOdd) {
                    matchingNum = sequenceNum + 1;
                } else {
                    matchingNum = sequenceNum - 1;
                }
                if (audioHolder.containsKey(matchingNum)) {
                    byte[] oddblock;
                    byte[] evenblock;

                    if (isOdd) {
                        oddblock = decryptedBlock;
                        evenblock = audioHolder.get(matchingNum);
                    } else {
                        oddblock = audioHolder.get(matchingNum);
                        evenblock = decryptedBlock;
                    }
                    byte[] num1 = new byte[512];
                    byte[] num2 = new byte[512];
                    byte[] num3 = new byte[512];
                    byte[] num4 = new byte[512];

                    System.arraycopy(oddblock, 0, num1, 0, 512);
                    System.arraycopy(oddblock, 512, num2, 0, 512);
                    System.arraycopy(evenblock, 0, num3, 0, 512);
                    System.arraycopy(evenblock, 512, num4, 0, 512);

                    player.playBlock(num1);
                    player.playBlock(num2);
                    player.playBlock(num3);
                    player.playBlock(num4);

                    lastAudio = num4;
                    audioHolder.remove(sequenceNum);
                    audioHolder.remove(matchingNum);

                    if (sequenceNum > matchingNum) {
                        preSeqNum = sequenceNum;
                    } else {
                        preSeqNum = matchingNum;
                    }               
                } else {
                    if (sequenceNum > (preSeqNum + 2)) {
                        byte[] b1 = new byte[512];
                        byte[] b2 = new byte[512];

                        System.arraycopy(decryptedBlock, 0, b1, 0, 512);
                        System.arraycopy(decryptedBlock, 512, b2, 0, 512);

                        player.playBlock(b1);
                        player.playBlock(b2);

                        audioHolder.remove(sequenceNum);
                        preSeqNum = sequenceNum;
                    }
                }

            } catch (IOException e) {
                System.out.println("ERROR: TextReceiver encountered an issue!");
                e.printStackTrace();
            }
        }
        receiving_socket2.close();
        System.out.println(receivedSequenceNumbers);
        System.out.println(receivedSequenceNumbers.size());
        System.out.println(count);
    }

}