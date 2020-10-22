package rmidemo.rmiinterface;

import java.io.Serializable;

public class Login implements Serializable{
	private byte[] username;
	private byte[] password;

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
