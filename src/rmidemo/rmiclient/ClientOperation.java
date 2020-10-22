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
import rmidemo.rmiinterface.RMIInterface;

public class ClientOperation {

	private static BufferedReader bufferReader = new BufferedReader(new InputStreamReader(System.in));
	private static RMIInterface server;


	private static String username = "";
	private static String password = "";
	private static UUID session;
	private static DiffeHillmanClient diffeHillmenClient;
	
	private static UUID login() throws NoSuchPaddingException, Exception
	{
		Login login = new Login();
		System.out.print("Username: ");
		username = bufferReader.readLine();
		byte [] encryptedUsername = diffeHillmenClient.doSymmetricEncryption(username);
		login.setUsername(encryptedUsername);
		System.out.print("Password: ");
		password = bufferReader.readLine();
		byte [] encryptedPassword = diffeHillmenClient.doSymmetricEncryption(password);
		login.setPassword(encryptedPassword);
		return server.login(login);
	}
	private static void refreshAuth() throws NoSuchPaddingException, Exception
	{
		while (!server.isLoggedIn(username))
		{
			session = login();
		}
	}

	private static void execute(int cmd) throws NoSuchPaddingException, Exception
	{
		String filename;
		byte[] Encryptedfilename;
		String printer;
		byte[] encryptedPrinter;
		int job;
		String parameter;
		String value;
		switch (cmd)
		{
			case 1:
				System.out.print("Filename: ");
				filename = bufferReader.readLine();
				
			    Encryptedfilename = diffeHillmenClient.doSymmetricEncryption(filename);
				System.out.print("Printer: ");
				printer = bufferReader.readLine();
				encryptedPrinter = diffeHillmenClient.doSymmetricEncryption(printer);
				refreshAuth();
				Printing print = new Printing(Encryptedfilename,encryptedPrinter);
				server.sendPrintingObject(print);
				//System.out.println(server.print(encodedParams,Encryptedfilename, encryptedPrinter, session));
				break;

			case 2:
				System.out.print("Printer: ");
				printer = bufferReader.readLine();

				refreshAuth();
				System.out.println(server.queue(printer, session));
				break;

			case 3:
				System.out.print("Printer: ");
				printer = bufferReader.readLine();
				System.out.print("Job: ");
				job = Integer.parseInt(bufferReader.readLine());

				refreshAuth();
				System.out.println(server.topQueue(printer, job, session));
				break;

			case 4:
				refreshAuth();
				System.out.println(server.start(session));
				break;

			case 5:
				refreshAuth();
				System.out.println(server.stop(session));
				break;

			case 6:
				refreshAuth();
				System.out.println(server.restart(session));
				break;

			case 7:
				System.out.print("Printer: ");
				printer = bufferReader.readLine();

				refreshAuth();
				System.out.println(server.status(printer, session));
				break;

			case 8:
				System.out.print("Parameter: ");
				parameter = bufferReader.readLine();

				refreshAuth();
				System.out.println(server.readConfig(parameter, session));
				break;

			case 9:
				System.out.print("Parameter: ");
				parameter = bufferReader.readLine();
				System.out.print("Value: ");
				value = bufferReader.readLine();

				refreshAuth();
				System.out.println(server.setConfig(parameter, value, session));
				break;

			case 0:
				System.out.println("Quitting...");
		}
	}

	public static void main(String[] args) throws MalformedURLException, RemoteException, NotBoundException {
		
		//server = (RMIInterface) Naming.lookup("//localhost/MyServer");
		 server = (RMIInterface)Naming.lookup("rmi://localhost:5099/MyServer");

		try {
			int requestedOperation = -1;
			 diffeHillmenClient = new DiffeHillmanClient();
			 diffeHillmenClient.DiffeHillmenInit();
			 byte[] alicePubKeyEnc = diffeHillmenClient.getAlicePubKeyEnc();
			 //return remote public key of server
			 byte[] serverPubKeyEnc = server.DiffeHillmenServer(alicePubKeyEnc);
			 diffeHillmenClient.setServerPubKeyEnc(serverPubKeyEnc);
			 diffeHillmenClient.generateSharedSecret();
			 diffeHillmenClient.initSymmetricConnection();
			 server.setAESEncodedParams(diffeHillmenClient.getEncodedParams());
			while (requestedOperation != 0)
			{
				System.out.println();
				System.out.println("1. print");
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
				execute(requestedOperation);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
