package dcmm;

public class DcmmTls {
    private String caFile = "";
    private String caPath = "";
    private String certFile = "";
    private String keyFile = "";

    public DcmmTls(String caFile, String caPath,
            String certFile, String keyFile) {
        this.caFile = caFile;
        this.caPath = caPath;
        this.certFile = certFile;
        this.keyFile = keyFile;
    }

    public DcmmTls() {}

    public String getCaFile() {
        return this.caFile;
    }

    public String getCaPath() {
        return this.caPath;
    }

    public String getCertFile() {
        return this.certFile;
    }

    public String getKeyFile() {
        return this.keyFile;
    }

    public void setCaFile(String caFile) {
        this.caFile = caFile;
    }

    public void setCaPath(String caPath) {
        this.caPath = caPath;
    }

    public void setCertFile(String certFile) {
        this.certFile = certFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }
}

