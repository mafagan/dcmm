import dcmm.*;

public class JavaHttp {
    public static void main(String[] args) throws Exception {
        System.loadLibrary("dcmmjni");
        byte[] bytes = new byte[50000];
        Dcmm.httpHttpsGet("http://www.baidu.com", bytes, 50000);
        String recvMsg = new String(bytes, "UTF-8");
        System.out.printf(recvMsg);
    }
}
