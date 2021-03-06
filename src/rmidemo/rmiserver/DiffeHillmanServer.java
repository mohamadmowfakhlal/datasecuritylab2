package rmidemo.rmiserver;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DiffeHillmanServer {
	private byte[] serverPubKeyEnc;
	private byte[] sharedSecret;
	private byte[] encodedParams;
	private Cipher cipher;
	KeyAgreement keyAgree;

	public byte[] getSharedSecret() {
		return sharedSecret;
	}

	public void DiffeHillmanServer() {

	}

	public void setSharedSecret(byte[] sharedSecret) {
		this.sharedSecret = sharedSecret;
	}

	public byte[] initDiffeHillmanServerAndGenerateSharedKey(byte[] clientPubKeyEnc) throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {

		KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);

		PublicKey clientPubKey = bobKeyFac.generatePublic(x509KeySpec);

		/*
		 * Bob gets the DH parameters associated with Alice's public key. He must use
		 * the same parameters when he generates his own key pair.
		 */
		DHParameterSpec dhParamFromClientPubKey = ((DHPublicKey) clientPubKey).getParams();

		// Bob creates his own DH key pair
		System.out.println("server: Generate DH keypair ...");
		KeyPairGenerator KpairGenerator = KeyPairGenerator.getInstance("DH");
		KpairGenerator.initialize(dhParamFromClientPubKey);
		KeyPair serverKpair = KpairGenerator.generateKeyPair();

		// Bob creates and initializes his DH KeyAgreement object
		System.out.println("server: Initialization ...");
		keyAgree = KeyAgreement.getInstance("DH");
		keyAgree.init(serverKpair.getPrivate());

		// Bob encodes his public key, and sends it over to Alice.
		serverPubKeyEnc = serverKpair.getPublic().getEncoded();

		/*
		 * Bob uses Alice's public key for the first (and only) phase of his version of
		 * the DH protocol.
		 */
		System.out.println("server: Execute PHASE1 ...");
		keyAgree.doPhase(clientPubKey, true);
		/*
		 * At this stage, both Alice and Bob have completed the DH key agreement
		 * protocol. Both generate the (same) shared secret.
		 */

		sharedSecret = keyAgree.generateSecret();
		// provide output buffer of required size
		System.out.println("server share secret: ");
		return serverPubKeyEnc;
	}

	public void initSymmetricConnection() throws NoSuchAlgorithmException, IOException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		/*
		 * Alice decrypts, using AES in CBC mode
		 */
		SecretKeySpec bobAesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
		/*
		 * Alice decrypts, using AES in CBC mode
		 */
		AlgorithmParameters aesParams = null;
		// Instantiate AlgorithmParameters object from parameter encoding
		// obtained from Bob
		aesParams = AlgorithmParameters.getInstance("AES");
		try {
			aesParams.init(getEncodedParams());
		} catch (IOException e) {
			e.printStackTrace();
		}
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, bobAesKey, aesParams);
	}

	public String doSymmetricEncryption(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
		byte[] recovered = cipher.doFinal(ciphertext);
		String retrivemessage = new String(recovered);

		return retrivemessage;
	}

	private static void byte2hex(byte b, StringBuffer buf) {
		char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		int high = ((b & 0xf0) >> 4);
		int low = (b & 0x0f);
		buf.append(hexChars[high]);
		buf.append(hexChars[low]);
	}

	/*
	 * Converts a byte array to hex string
	 */
	private static String toHexString(byte[] block) {
		StringBuffer buf = new StringBuffer();
		int len = block.length;
		for (int i = 0; i < len; i++) {
			byte2hex(block[i], buf);
			if (i < len - 1) {
				buf.append(":");
			}
		}
		return buf.toString();
	}

	public byte[] getEncodedParams() {
		return encodedParams;
	}

	public void setEncodedParams(byte[] encodedParams) {
		this.encodedParams = encodedParams;
	}
	public boolean calculateMac(byte[] receiveMac,byte[] bytes) throws NoSuchAlgorithmException {
	      Mac mac = Mac.getInstance("HmacSHA256");
	      SecretKeySpec key = new SecretKeySpec(sharedSecret, 0, 16, "AES");
	      try {
			mac.init(key);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	      byte[] macResult = mac.doFinal(bytes);
		return Arrays.equals(receiveMac,macResult);
	}
}
