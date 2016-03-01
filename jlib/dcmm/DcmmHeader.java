package dcmm;

public class DcmmHeader {
    private String magic = "";
    private long version;
    private short type;
    private int length;
    private long msgId;
    private long cfmId;
    private short opt;
    private short flags;
    private int reserved;

    public DcmmHeader(String magic, long version, short type,
            int length, long msgId, long cfmId, short opt,
            short flags) {
        this.magic = magic;
        this.version = version;
        this.type = type;
        this.length = length;
        this.msgId = msgId;
        this.cfmId = cfmId;
        this.opt = opt;
        this.flags = flags;
    }

    public DcmmHeader() {}

    public String getMagic() {
        return this.magic;
    }

    public long getVersion() {
        return this.version;
    }

    public short getType() {
        return this.type;
    }

    public int getLength() {
        return this.length;
    }

    public long getMsgId() {
        return this.msgId;
    }

    public long getCfmId() {
        return this.cfmId;
    }

    public short getOpt() {
        return this.opt;
    }

    public short getFlags() {
        return this.flags;
    }

    public int getReserved() {
        return this.reserved;
    }

    public void setMagic(String magic) {
        this.magic = magic;
    }

    public void setVersion(long version) {
        this.version = version;
    }

    public void setType(short type) {
        this.type = type;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public void setMsgId(long msgId) {
        this.msgId = msgId;
    }

    public void setCfmId(long cfmId) {
        this.cfmId = cfmId;
    }

    public void setOpt(short opt) {
        this.opt = opt;
    }

    public void setFlags(short flags) {
        this.flags = flags;
    }
}


