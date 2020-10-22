package rmidemo.rmiinterface;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Password {
	private byte[] hashedsaltedPassword;
	private byte[] salt;
	public byte[] getHashedPassword() {
		return hashedsaltedPassword;
	}

	public void setHashedPassword(byte[] hashedPassword) {
		this.hashedsaltedPassword = hashedPassword;
	}

	public byte[] getSalt() {
		return salt;
	}

	public void setSalt(byte[] salt) {
		this.salt = salt;
	}
	public boolean verify(String pass) throws NoSuchAlgorithmException {
	 	  //using the sha512 to hash the password 
	 	  MessageDigest md = MessageDigest.getInstance("SHA-512");
	 	  md.update(salt);
	 	  byte[] hashedPass = md.digest(pass.getBytes(StandardCharsets.UTF_8));
	 	  
		return Arrays.equals(hashedsaltedPassword,hashedPass);
	}
}
