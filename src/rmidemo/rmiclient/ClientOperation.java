package rmidemo.rmiclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import rmidemo.rmiinterface.Login;
import rmidemo.rmiinterface.Printing;
import rmidemo.rmiinterface.PrintingInterface;
import rmidemo.rmiinterface.Registeration;

public class ClientOperation {

	private static BufferedReader bufferReader = new BufferedReader(new InputStreamReader(System.in));
	private static PrintingInterface server;

	private static String username = "";
	private static String password = "";
	private static String role = "";
	private static UUID session;
	private static DiffeHillmanClient diffeHillmenClient;

	private static UUID login() throws NoSuchPaddingException, Exception {
		Login login = new Login();
		System.out.print("Username: ");
		username = bufferReader.readLine();
		byte[] encryptedUsername = diffeHillmenClient.doSymmetricEncryption(username);

		System.out.print("Password: ");
		password = bufferReader.readLine();
		byte[] encryptedPassword = diffeHillmenClient.doSymmetricEncryption(password);
		byte[] bytes = new byte[encryptedUsername.length + encryptedPassword.length];
		System.arraycopy(encryptedUsername, 0, bytes, 0, encryptedUsername.length);
		System.arraycopy(encryptedPassword, 0, bytes, encryptedUsername.length, encryptedPassword.length);
		byte[] mac;
		mac = diffeHillmenClient.calculateMac(bytes);

		login.setMac(mac);
		login.setUsername(encryptedUsername);
		login.setPassword(encryptedPassword);
		return server.login(login);
	}

	private static void register() throws NoSuchPaddingException, Exception {

		System.out.print("Username: ");
		username = bufferReader.readLine();
		byte[] encryptedUsername = diffeHillmenClient.doSymmetricEncryption(username);

		System.out.print("Password: ");
		password = bufferReader.readLine();
		byte[] encryptedPassword = diffeHillmenClient.doSymmetricEncryption(password);

		System.out.print("the role of user: ");
		role = bufferReader.readLine();
		byte[] encryptedType = diffeHillmenClient.doSymmetricEncryption(role);

		byte[] mac;
		byte[] bytes = new byte[encryptedUsername.length + encryptedPassword.length + encryptedType.length];
		System.arraycopy(encryptedUsername, 0, bytes, 0, encryptedUsername.length);
		System.arraycopy(encryptedPassword, 0, bytes, encryptedUsername.length, encryptedPassword.length);
		System.arraycopy(encryptedType, 0, bytes, encryptedPassword.length, encryptedType.length);
		mac = diffeHillmenClient.calculateMac(bytes);
		Registeration registration = new Registeration(encryptedUsername, encryptedPassword, encryptedType, mac);
		// registration.setMac(mac);
		// registration.setUsername(encryptedUsername);
		// registration.setPassword(encryptedPassword);
		// registration.setType(encryptedType);
		server.register(registration);
	}

	private static void refreshAuthentication() throws NoSuchPaddingException, Exception {
		while (!server.isLoggedIn(username)) {
			session = login();
		}
	}

	private static void executeClientCommand(int cmd) throws NoSuchPaddingException, Exception {
		String filename;
		byte[] encryptedfilename;
		String printer;
		byte[] encryptedPrinter;
		byte[] mac;
		int job;
		String parameter;
		String value;
		switch (cmd) {
		case -2:
			System.out.println("Registeration...");
			register();
			break;
		case 1:
			System.out.print("Enter the Filename that you to print: ");
			filename = bufferReader.readLine();
			encryptedfilename = diffeHillmenClient.doSymmetricEncryption(filename);
			System.out.print("Ener the Printer name where you want to print file: ");
			printer = bufferReader.readLine();
			encryptedPrinter = diffeHillmenClient.doSymmetricEncryption(printer);
			refreshAuthentication();
			byte[] bytes = new byte[encryptedfilename.length + encryptedPrinter.length];
			System.arraycopy(encryptedfilename, 0, bytes, 0, encryptedfilename.length);
			System.arraycopy(encryptedPrinter, 0, bytes, encryptedfilename.length, encryptedPrinter.length);
			mac = diffeHillmenClient.calculateMac(bytes);
			Printing print = new Printing(encryptedfilename, encryptedPrinter, mac);
			server.print(print, session);
			break;
		case 2:
			System.out.print(
					"Enter the Printer name that you want to show the list of job that is waiting to be done in it: ");
			printer = bufferReader.readLine();

			refreshAuthentication();
			System.out.println(server.queue(printer, session));
			break;

		case 3:
			System.out.print("Enter the Printer name that you want to change the order in: ");
			printer = bufferReader.readLine();
			System.out.print("Enter the Job id that you want to give high prority: ");
			job = Integer.parseInt(bufferReader.readLine());

			refreshAuthentication();
			System.out.println(server.topQueue(printer, job, session));
			break;

		case 4:
			System.out.print("start the server if it is not already started");
			refreshAuthentication();
			System.out.println(server.start(session));
			break;

		case 5:
			System.out.print("stop the server ");
			refreshAuthentication();
			System.out.println(server.stop(session));
			break;

		case 6:
			System.out.print("restart the server");
			refreshAuthentication();
			System.out.println(server.restart(session));
			break;

		case 7:
			System.out.print("Enter the Printer name that you want to show the status: ");
			printer = bufferReader.readLine();

			refreshAuthentication();
			System.out.println(server.status(printer, session));
			break;

		case 8:
			System.out.print("Enter the Parameter name : ");
			parameter = bufferReader.readLine();

			refreshAuthentication();
			System.out.println(server.readConfig(parameter, session));
			break;

		case 9:
			System.out.print("Enter the Parameter name : ");
			parameter = bufferReader.readLine();
			System.out.print("Value of the parameter is: ");
			value = bufferReader.readLine();

			refreshAuthentication();
			System.out.println(server.setConfig(parameter, value, session));
			break;

		case 0:
			System.out.println("Quitting...");

		}
	}

	public static void main(String[] args) throws MalformedURLException, RemoteException, NotBoundException {

		server = (PrintingInterface) Naming.lookup("rmi://localhost:5199/MyServer");

		try {
			int requestedOperation = -1;
			// create diffe-hillman client
			diffeHillmenClient = new DiffeHillmanClient();
			// Initialize diffe-hillman return public key of client which is sent in the
			// channel
			byte[] clientPubKeyEnc = diffeHillmenClient.init();
			// return remote public key of server
			byte[] serverPubKeyEnc = server.initDiffeHillmenServer(clientPubKeyEnc);
			diffeHillmenClient.setServerPubKeyEnc(serverPubKeyEnc);
			// create the shared key from both client and server public key
			diffeHillmenClient.generateSharedSecret();
			// use the key in symmetric encryption
			diffeHillmenClient.initSymmetricConnection();
			byte[] encodedparams = diffeHillmenClient.getEncodedParams();
			// because we are using AES we need to send the public parameter to another
			// party as an inilization vector
			server.initSymmetricConnection(encodedparams);
			while (requestedOperation != 0) {
				System.out.println();
				System.out.println("-2. register");
				System.out.println("1. printing");
				System.out.println("2. queue");
				System.out.println("3. topQueue");
				System.out.println("4. start");
				System.out.println("5. stop");
				System.out.println("6. restart");
				System.out.println("7. status");
				System.out.println("8. readConfig");
				System.out.println("9. setConfig");
				System.out.println("0. quit");
				System.out.print(">");

				requestedOperation = Integer.parseInt(bufferReader.readLine());
				executeClientCommand(requestedOperation);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
