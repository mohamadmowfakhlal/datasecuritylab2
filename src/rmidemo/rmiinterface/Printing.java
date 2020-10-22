package rmidemo.rmiinterface;

import java.io.Serializable;

public class Printing implements Serializable{

	/**
	 * 
	 */
	public  Printing(byte[] filename,byte[] printer) {
		this.filename = filename;
		this.printer = printer;
	}
	private static final long serialVersionUID = 1L;
	private byte[] filename;
	private byte[] printer;
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
