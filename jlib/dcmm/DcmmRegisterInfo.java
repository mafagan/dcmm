package dcmm;

public class DcmmRegisterInfo {
    private int priority;

    public DcmmRegisterInfo(int priority) {
        this.priority = priority;
    }

    public DcmmRegisterInfo() {}

    public int getPriority() {
        return this.priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }
}


