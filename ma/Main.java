public class Main {
    public static void main(String[] args) {

        Thread senderThread = new Thread(()  -> {
            try{
                TextSenderThread.main(new String[]{});
            }
            catch(Exception e){
                e.printStackTrace();
            }
        });
        
        Thread receiverThread = new Thread(() -> {
            try{
                TextRecieverThread.main(new String[]{}) ;
            }
            catch(Exception e){
                e.printStackTrace();
            }
        });

        senderThread.start();
        receiverThread.start();
    }

    // public void run(){
    //     System.out.println("running");
    // }
}
    

