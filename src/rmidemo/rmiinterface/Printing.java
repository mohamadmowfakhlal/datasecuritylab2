package rmidemo.rmiinterface;

import java.io.Serializable;

public class Printing  implements Serializable{

	private static final long serialVersionUID = 1L;
	private byte[] filename;
	private byte[] printer;
	private byte[] mac;

	public byte[] getMac() {
		return mac;
	}

	public void setMac(byte[] mac) {
		this.mac = mac;
	}

	/**
	 * 
	 */
	public  Printing(byte[] filename,byte[] printer,byte[] mac) {
		this.filename = filename;
		this.printer = printer;
		this.mac = mac;
	}

	public byte[] getFilename() {
		return filename;
	}
	public void setFilename(byte[] filename) {
		this.filename = filename;
	}
	public byte[] getPrinter() {
		return printer;
	}
	public void setPrinter(byte[] printer) {
		this.printer = printer;
	}
}
