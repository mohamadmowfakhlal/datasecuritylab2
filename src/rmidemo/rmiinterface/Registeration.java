package rmidemo.rmiinterface;

import java.io.Serializable;

public class Registeration implements Serializable{
	private static final long serialVersionUID = 3L;
	private byte[] username;
	private byte[] password;
	private byte[] mac;

	public byte[] getMac() {
		return mac;
	}

	public void setMac(byte[] mac) {
		this.mac = mac;
	}

	public byte[] getUsername() {
		return username;
	}
	public void setUsername(byte[] username) {
		this.username = username;
	}
	public byte[] getPassword() {
		return password;
	}
	public void setPassword(byte[] password) {
		this.password = password;
	}
}
