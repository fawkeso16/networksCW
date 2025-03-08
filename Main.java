public class Main {
    public static void main(String[] args) {

        Thread senderThread = new Thread(()  -> {
            try{
                TextSenderThread.main(new String[]{});
            }
            catch(Exception e){
                System.err.println("sender thread error");
            }
        });
        
        Thread receiverThread = new Thread(() -> {
            try{
                TextRecieverThread.main(new String[]{}) ;
            }
            catch(Exception e){
                System.err.println("reciever thread error");

            }
        });

        senderThread.start();
        receiverThread.start();
    }

    // public void run(){
    //     System.out.println("running");
    // }
}
    

