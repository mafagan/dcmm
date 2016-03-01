package dcmm;

public class Dcmm {
    public native DcmmHeader getStruct();
    public native void test();

    public native int init();
    public native void destroy();
    public native int socket(int type);
    public native int registerSession(int dsocket,
            int priority);
    public native int connect(int dsocket, DcmmAddr addr,
            int options, Timeval timeout);
    public native int disconnect(int dsocket);
    public native int sendEx(int dsocket, byte[] data,
            long size, int options, Timeval timeout);
    public native int send(int dsocket, byte[] data, long size);
    public native int recvEx(int dsocket, byte[] data,
            long size, int options, Timeval timeout);
    public native int recv(int dsocket, byte[] data, long size);
    public native int status(int dsocket, DcmmStatus status);
    public native int close(int dsocket);
    public native int delete(int dsocket);
    public native int tlsSet(int dsocket, String caFile,
            String caPath, String certFile, String keyFile);
    public static native int httpHttpsGet(String url, byte[] buff,
            int maxSize);

}


