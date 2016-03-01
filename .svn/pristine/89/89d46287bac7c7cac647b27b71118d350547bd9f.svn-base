import dcmm.*;
/**
 * compile:
 *      javac -cp .:../jlib/dcmm.jar JavaTest.java
 * run by:
 *      java -Djava.library.path=../jlib/ -cp .:../jlib/dcmm.jar JavaTest
 */
public class JavaTest {
    public static void main(String[] args) throws Exception {
        System.loadLibrary("dcmmjni");
        Dcmm dcmm = new Dcmm();

        Timeval timeval = new Timeval(5, 0);
        DcmmAddr dcmmAdddr = new DcmmAddr(9000, "127.0.0.1");
        int dsocket = dcmm.socket(0);

        if (dsocket == -1) {
            System.out.println("dcmm_socket");
        }
        System.out.printf("connection status: %d\n", dcmm.connect(dsocket, dcmmAdddr, 3, timeval));
        String msg;
        for (int i = 0; i < 20; ++i) {
            msg = i + "hello";
            byte[] buff = msg.getBytes();
            System.out.printf("start to send msg : %s\n", msg);
            dcmm.send(dsocket, buff, buff.length);
        }

        dcmm.registerSession(dsocket, 1);

        System.out.printf("begin to send 8 messages\n");
        for (int i = 0; i < 8; ++ i) {
            int j = i + 20;
            msg = j + "hello";
            byte[] buff = msg.getBytes();
            dcmm.send(dsocket, buff, buff.length);
        }
        byte[] recv_buff = new byte[100];
        int recv_length = 0;
        recv_length = dcmm.recv(dsocket, recv_buff, 100);
        String recv_msg = new String(recv_buff, "UTF-8");
        System.out.printf("%d\n", recv_length);
        System.out.printf("%s\n", recv_msg);

        dcmm.close(dsocket);
    }

}
