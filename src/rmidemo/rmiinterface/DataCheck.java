package rmidemo.rmiinterface;

public class DataCheck {
	private byte[] mac;

	public byte[] getMac() {
		return mac;
	}

	public void setMac(byte[] mac) {
		this.mac = mac;
	}
	public  DataCheck(byte[] mac) {
		this.mac = mac;
	}
}
