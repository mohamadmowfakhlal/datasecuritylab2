package rmidemo.rmiserver;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;

import rmidemo.rmiinterface.AccessControlListRow;
import rmidemo.rmiinterface.Login;
import rmidemo.rmiinterface.Printing;
import rmidemo.rmiinterface.PrintingInterface;
import rmidemo.rmiinterface.Registeration;
import rmidemo.rmiinterface.Password;
import rmidemo.rmiinterface.PolicyManagment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.AbstractMap.SimpleEntry;

public class ServerOperation extends UnicastRemoteObject implements PrintingInterface {

	private HashMap<String, String> config = new HashMap<String, String>();
	private HashMap<UUID, Entry<String, LocalDateTime>> userSessionMap = new HashMap<UUID, Entry<String, LocalDateTime>>();
	private HashMap<UUID,String> sessionRole= new HashMap<UUID,String>();
	private HashMap<UUID,String> userSession= new HashMap<UUID,String>();

	// private HashMap<String, String> userPassMap = new HashMap<String, String>();
	// private HashMap<String, Password> userRigerterationMap = new HashMap<String,
	// Password>();
	private HashMap<String, ArrayList<String>> queue = new HashMap<String, ArrayList<String>>();

	private static final int TIMEOUT = 300; // Timeout in seconds
	private static final long serialVersionUID = 1L;
	private static DiffeHillmanServer diffeHillmanserver;
	private boolean isRunning = false;

	@Override
	public void register(Registeration registration) throws NoSuchPaddingException, Exception {
		Password pass = new Password();
		String username = decryptCipherText(registration.getUsername());
		String password = decryptCipherText(registration.getPassword());
		String type = decryptCipherText(registration.getType());
		// generating a random salt
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[16];
		random.nextBytes(salt);
		pass.setSalt(salt);
		// using the sha512 to hash the password
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		md.update(salt);
		byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
		pass.setHashedPassword(hashedPassword);
		pass.setUsername(username);
		pass.setType(type);
		// Todo here we need to check if the user already exit
		saveRegisteration(pass);
		// userRigerterationMap.put(username,pass);
		System.out.println("register(" + username);
		// check integrity
	      byte[] bytes = new byte[registration.getUsername().length + registration.getPassword().length + registration.getType().length];
	      System.arraycopy(registration.getUsername(), 0, bytes, 0, registration.getUsername().length);
	      System.arraycopy(registration.getPassword(), 0, bytes, registration.getUsername().length, registration.getPassword().length);
	      System.arraycopy(registration.getType(), 0, bytes, registration.getPassword().length, registration.getType().length);

	      if (diffeHillmanserver.calculateMac(registration.getMac(),bytes))
	    	  System.out.println("correct registeration data received");
	}

	public void WriteObjectToFile(Object serObj, String filepath) {

		try {
			File passwordFile = new File(filepath);
			System.out.println(passwordFile.length());
			if (passwordFile.length() != 0) {
				FileOutputStream fileOut = new FileOutputStream(filepath, true);

				ObjectOutputStream objectOut = new ObjectOutputStream(fileOut) {
					protected void writeStreamHeader() throws IOException {
						reset();
					}
				};
				objectOut.writeObject(serObj);
				objectOut.close();
				fileOut.close();
				System.out.println("The Object  was succesfully written to a file");
			} else {
				FileOutputStream fileOut = new FileOutputStream(filepath, true);
				ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
				objectOut.writeObject(serObj);
				objectOut.close();
				fileOut.close();
				System.out.println("The Object  was succesfully written to a file");
			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	public String addandupdateuserpermssion(String username, ArrayList<String> perm,UUID session) throws Exception, FileNotFoundException, ClassNotFoundException, IOException {
		AccessControlListRow userpermmsions= searchforPermmsion(username);
		AccessControlListRow newAccess = new AccessControlListRow(username,perm);
		if(userpermmsions == null) {
			WriteObjectToFile(newAccess, "AccessControlListPolicy.txt");
			return "successfull add";
		}else {
			//delete old entry and add new permission			
		    {
		        List<AccessControlListRow> objects = readObjectsFromFile("AccessControlListPolicy.txt");
		        for(AccessControlListRow r : objects)
		        	if(r.getUser().equals(userpermmsions.getUser())) {
		        		objects.remove(r);
		        		break;
		        	}
		        objects.add(newAccess);
		        writeObjectsToFile("AccessControlListPolicy.txt", objects);
		      }
			return "successfull add and remove";
		}
	
	}

	
	public void removeUserPolicy(String username) throws IOException, ClassNotFoundException {
		 
		        List<AccessControlListRow> objects = readObjectsFromFile("AccessControlListPolicy.txt");
		        for(AccessControlListRow r : objects)
		        	if(r.getUser().equals(username)) {
		        		objects.remove(r);
		        		break;
		        	}
		        writeObjectsToFile("AccessControlListPolicy.txt", objects);
	}
	
	private static AccessControlListRow searchforPermmsion(String username) throws FileNotFoundException, IOException, ClassNotFoundException {
		AccessControlListRow pr1;
		 File newFile = new File("AccessControlListPolicy.txt");

		    if (newFile.length() == 0)
		    	return null;
		FileInputStream fi = new FileInputStream(new File("AccessControlListPolicy.txt"));
		ObjectInputStream oi = new ObjectInputStream(fi);
		while (true) {
			try {
				pr1 = (AccessControlListRow) oi.readObject();
				if (pr1.getUser().equals(username)) {
					fi.close();
					oi.close();
					return pr1;
				}

			} catch (EOFException e) {
				fi.close();
				oi.close();
				return null;
			}

		}
	}
	  private static void writeObjectsToFile(String filename, List objects) throws IOException {
		    OutputStream os = null;
		    try {
		      os = new FileOutputStream(filename);
		      ObjectOutputStream oos = new ObjectOutputStream(os);
		      for (Object object : objects) {
		        oos.writeObject(object);
		      }
		      oos.flush();
		    } finally {
		      if (os != null) {
		        os.close();
		      }
		    }
		  }

		  private static List readObjectsFromFile(String filename) throws IOException, ClassNotFoundException {
		    List objects = new ArrayList();
		    InputStream is = null;
		    try {
		      is = new FileInputStream(filename);
		      ObjectInputStream ois = new ObjectInputStream(is);
		      while (true) {
		        try {
		          Object object = ois.readObject();
		          objects.add(object);
		        } catch (EOFException ex) {
		          break;
		        }
		      }
		    } finally {
		      if (is != null) {
		        is.close();
		      }
		    }
		    return objects;
		  }



	private void saveRegisteration(Password pass) {

		WriteObjectToFile(pass, "password.txt");
	}

	protected ServerOperation() throws Exception {
		super();
		//PolicyManagment.createPermmison();
		PolicyManagment.createRoleBasedAccessControl();
		//PolicyManagment.createAccessControlList();
	}

	private boolean authenticate(UUID session) {
		SimpleEntry<String, LocalDateTime> value = (SimpleEntry<String, LocalDateTime>) userSessionMap.get(session);
		 if ( value.getValue().isBefore(LocalDateTime.now().minusSeconds(TIMEOUT))) {
			 sessionRole.remove(session);
		 	userSession.remove(session);
		 }
		 return value == null ? false : !value.getValue().isBefore(LocalDateTime.now().minusSeconds(TIMEOUT));
	}

	private String getUsername(UUID session) {
		SimpleEntry<String, LocalDateTime> value = (SimpleEntry<String, LocalDateTime>) userSessionMap.get(session);

		return value == null ? "" : value.getKey();
	}

	@Override
	public boolean isLoggedIn(String username) {
		System.out.println("isLoggedIn(" + username + ")");

		for (Entry<UUID, Entry<String, LocalDateTime>> token : userSessionMap.entrySet()) {
			if (token.getValue().getKey().equals(username)) {
				return authenticate(token.getKey());
			}
		}
		return false;
	}

	@Override
	public UUID login(Login login) throws NoSuchPaddingException, Exception {
		// check integrity
	      byte[] bytes = new byte[login.getUsername().length + login.getPassword().length ];
	      System.arraycopy(login.getUsername(), 0, bytes, 0, login.getUsername().length);
	      System.arraycopy(login.getPassword(), 0, bytes, login.getUsername().length, login.getPassword().length);
			if (diffeHillmanserver.calculateMac(login.getMac(),bytes))
				System.out.println("correct login  data received");
			else {
				System.out.println("data login  data received is not correct please resent again");
				return null;
			} 
			//String username = decryptCipherText(login.getUsername());
			String username = diffeHillmanserver.doSymmetricEncryption(login.getUsername());
			//String password = decryptCipherText(login.getPassword());
			String password = diffeHillmanserver.doSymmetricEncryption(login.getPassword());
			Password logininfo = search(username);
			if (logininfo != null) {
				MessageDigest md = MessageDigest.getInstance("SHA-512");
				md.update(logininfo.getSalt());
				byte[] hashedPass = md.digest(password.getBytes(StandardCharsets.UTF_8));
				byte[] hashedsaltedPassword = logininfo.getHashedPassword();
				boolean correct = Arrays.equals(hashedsaltedPassword, hashedPass);
				if (correct)
					System.out.println("correct login info");
				else
					return null;
			}
			else {
				System.out.println("username is not registered login");
				return null;
			}
			String role = logininfo.getType();
			UUID session = UUID.randomUUID();
			userSessionMap.put(session, new SimpleEntry<String, LocalDateTime>(username, LocalDateTime.now()));
			sessionRole.put(session,role);
			userSession.put(session,username);

			System.out.println("login(" + username + ",)");


		return session;
	}

	private Password search(String username) throws FileNotFoundException, IOException, ClassNotFoundException {
		Password pr1;
		 File newFile = new File("password.txt");
		    if (newFile.length() == 0)
		    	return null;

		FileInputStream fi = new FileInputStream(new File("password.txt"));
		ObjectInputStream oi = new ObjectInputStream(fi);
		while (true) {
			try {
				pr1 = (Password) oi.readObject();
				if (pr1.getUsername().equals(username)) {
					fi.close();
					oi.close();
					return pr1;
				}

			} catch (EOFException e) {
				fi.close();
				oi.close();
				return null;
			}

		}
	}

	@Override
	public String queue(String printer, UUID session) throws Exception, ClassNotFoundException, IOException {
		if (!authenticate(session)) {
			return "The session has expire ";
		}
		
		//List<String> permissions = PolicyManagment.getPermmsionForRole( userRole.get(session));
		List<String> permissions = PolicyManagment.getPermssionForUser(userSession.get(session));
		if(permissions == null) {return "you are not authorized";}
		if(!permissions.contains("queue") )
			return "You are not authorized to access the queue";
		System.out.println(getUsername(session) + ": queue()" + sessionRole.get(session));
		
		if (!isRunning) {
			return "service is not running";
		}

		if (!queue.keySet().contains(printer)) {
			return "Queue is empty";
		}

		ArrayList<String> printerQueue = queue.get(printer);
		String queueStr = "";
		int c = 0;

		for (Iterator<String> i = printerQueue.iterator(); i.hasNext();) {
			c++;
			queueStr += String.format("%d: %s\n", c, i.next());
		}

		return queueStr;
	}

	@Override
	public String topQueue(String printer, int job, UUID session) throws FileNotFoundException, ClassNotFoundException, IOException {
		if (!authenticate(session)) {
			return "The session has expire ";
		}
//		List<String> permissions = PolicyManagment.getPermmsionForRole( sessionRole.get(session));
		List<String> permissions = PolicyManagment.getPermssionForUser(userSession.get(session));
		if(permissions == null) {return "you are not authorized";}
		if(!permissions.contains("topQueue") )
			return "You are not authorized to access the queue";
		System.out.println(getUsername(session) + ": topQueue(" + job + ")");
		
		if (!isRunning) {
			return "service is not running";
		}

		if (!queue.keySet().contains(printer)) {
			return "Queue is empty";
		}

		ArrayList<String> printerQueue = queue.get(printer);

		if (job > printerQueue.size() || job < 1) {
			return "Invalid job index!";
		}

		String targetJob = (String) printerQueue.get(job - 1);

		for (int i = job - 1; i > 0; i--) {
			printerQueue.set(i, printerQueue.get(i - 1));
		}

		printerQueue.set(0, targetJob);

		return "Job " + job + " moved to top of queue for " + printer;
	}

	@Override
	public String start(UUID session) throws FileNotFoundException, ClassNotFoundException, IOException  {
		if (!authenticate(session)) {
			return "The session has expire ";
		}
		//List<String> permissions = PolicyManagment.getPermmsionForRole( sessionRole.get(session));
		List<String> permissions = PolicyManagment.getPermssionForUser(userSession.get(session));
		if(permissions == null) {return "you are not authorized";}
		if(!permissions.contains("start") )
			return "You are not authorized to access the start";
		System.out.println(getUsername(session) + ": start()");
		
		if (isRunning) {
			return "Already running";
		}

		isRunning = true;
		return "Starting...";
	}

	@Override
	public String stop(UUID session)  throws FileNotFoundException, ClassNotFoundException, IOException  {
		if (!authenticate(session)) {
			return "The session has expire ";
		}
		//List<String> permissions = PolicyManagment.getPermmsionForRole( sessionRole.get(session));
		List<String> permissions = PolicyManagment.getPermssionForUser(userSession.get(session));
		
			if(permissions == null) {return "you are not authorized";}
		if(!permissions.contains("stop") )
			return "You are not authorized to access the stop";
		System.out.println(getUsername(session) + ": stop()");
		
		if (!isRunning) {
			return "Already stopped";
		}

		isRunning = false;
		queue = new HashMap<String, ArrayList<String>>();
		return "Stopping...";
	}

	@Override
	public String restart(UUID session)  throws FileNotFoundException, ClassNotFoundException, IOException  {
		if (!authenticate(session)) {
			return "The session has expire ";
		}
		//List<String> permissions = PolicyManagment.getPermmsionForRole( sessionRole.get(session));
		List<String> permissions = PolicyManagment.getPermssionForUser(userSession.get(session));
		if(permissions == null) {return "you are not authorized";}
		
		if(!permissions.contains("restart") )
			return "You are not authorized to access the restart";
		System.out.println(getUsername(session) + ": restart()");
		
		stop(session);
		start(session);
		return "Restarting...";
	}

	@Override
	public String status(String printer, UUID session) throws FileNotFoundException, ClassNotFoundException, IOException  {
		if (!authenticate(session)) {
			return "The session has expire ";
		}
//		List<String> permissions = PolicyManagment.getPermmsionForRole( sessionRole.get(session));
		List<String> permissions = PolicyManagment.getPermssionForUser(userSession.get(session));
		if(permissions == null) {return "you are not authorized";}
		if(!permissions.contains("status") )
			return "You are not authorized to access the status";
		System.out.println(getUsername(session) + ": status()");
		
		if (!isRunning) {
			return "service is not running";
		}

		if (!queue.keySet().contains(printer)) {
			return "Queue is empty";
		}

		ArrayList<String> printerQueue = queue.get(printer);

		if (printerQueue == null || printerQueue.isEmpty()) {
			return printer + " is available";
		}

		return printer + " is busy (queue length: " + printerQueue.size() + ")";
	}

	@Override
	public String readConfig(String parameter, UUID session) throws FileNotFoundException, ClassNotFoundException, IOException {
		if (!authenticate(session)) {
			return "The session has expire ";
		}
		//List<String> permissions = PolicyManagment.getPermmsionForRole( sessionRole.get(session));
		List<String> permissions = PolicyManagment.getPermssionForUser(userSession.get(session));
		if(permissions == null) {return "you are not authorized";}
		
		if(!permissions.contains("readConfig") )
			return "You are not authorized to access the readconfig";
		System.out.println(getUsername(session) + ": readConfig(" + parameter + ")");
		
		String confValue = config.get(parameter);

		return confValue == null ? "" : confValue;
	}

	@Override
	public byte[] initDiffeHillmenServer(byte[] clientPubKeyEnc) throws RemoteException, Exception {
		diffeHillmanserver = new DiffeHillmanServer();
		return diffeHillmanserver.initDiffeHillmanServerAndGenerateSharedKey(clientPubKeyEnc);
	}

	public String decryptCipherText(byte[] ciphertext) throws Exception, NoSuchPaddingException {
		
		return diffeHillmanserver.doSymmetricEncryption(ciphertext);
	}

	@Override
	public void initSymmetricConnection(byte[] encodedParams) throws Exception{
		diffeHillmanserver.setEncodedParams(encodedParams);
		diffeHillmanserver.initSymmetricConnection();
	}

	@Override
	public String setConfig(String parameter, String value, UUID session) throws FileNotFoundException, ClassNotFoundException, IOException {
		if (!authenticate(session)) {
			return "The session has expire ";
		}
		//List<String> permissions = PolicyManagment.getPermmsionForRole( sessionRole.get(session));
		List<String> permissions = PolicyManagment.getPermssionForUser(userSession.get(session));
		if(permissions == null) {return "you are not authorized";}
		
		if(!permissions.contains("setConfig") )
			return "You are not authorized to access the queue";
		System.out.println(getUsername(session) + ": setConfig(" + parameter + "," + value + ")");
		
		config.put(parameter, value);

		return "Set parameter " + parameter + " to " + value;
	}

	public static void main(String[] args) {
		try {
			File myObj = new File("password.txt");
			File myObj1 = new File("AccessControlListPolicy.txt");
			if (myObj.createNewFile()) {
				System.out.println("File created: " + myObj.getName());
			} else {
				System.out.println("File already exists.");
			}
			if (myObj1.createNewFile()) {
				System.out.println("File created: " + myObj1.getName());
			} else {
				System.out.println("File already exists.");
			}
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
		try {
			// System.setProperty("java.rmi.server.hostname","192.168.168.231");

			// Naming.rebind("//127.0.0.1/MyServer", new ServerOperation());
			System.out.println("Server ready");
			Registry registry = LocateRegistry.createRegistry(5199);
			registry.rebind("MyServer", new ServerOperation());
		} catch (Exception e) {

			System.out.println("Server exception: " + e.toString());
			e.printStackTrace();

		}

	}

	public String print(Printing print, UUID session) throws FileNotFoundException, ClassNotFoundException, IOException, NoSuchAlgorithmException, Exception, BadPaddingException {
		// System.out.println("printer"+print.getPrinter());
		// System.out.println("printer"+print.getFilename());
		// check integrity
	      byte[] bytes = new byte[print.getPrinter().length + print.getFilename().length ];
	      System.arraycopy(print.getFilename(), 0, bytes, 0, print.getFilename().length);
	      System.arraycopy(print.getPrinter(), 0, bytes, print.getFilename().length, print.getPrinter().length);
		if (diffeHillmanserver.calculateMac(print.getMac(), bytes))
			System.out.println("correct prininting data received");
		else {
			System.out.println(" prininting data received incorrectelly");
			return "your data has not been recieved try to send again";
		}

		if (!authenticate(session)) {
			return "The session has expire ";
		}
		List<String> permissions = PolicyManagment.getPermssionForUser(userSession.get(session));
		if(permissions == null) {return "you are not authorized";}
		
		if(!permissions.contains("print") )
			return "You are not authorized to access the print";
		
		String file = diffeHillmanserver.doSymmetricEncryption(print.getFilename());
		//String file = decryptCipherText(print.getFilename());
		String printer = diffeHillmanserver.doSymmetricEncryption(print.getPrinter());
		//String printer = decryptCipherText(print.getPrinter());
		System.out.println(getUsername(session) + ": print(" + file + "," + printer + ")");

		if (!isRunning) {
			return "Service is not running";
		}

		ArrayList<String> printerQueue;

		if (!queue.keySet().contains(printer)) {
			printerQueue = new ArrayList<String>();
			queue.put(printer, printerQueue);
		} else {
			printerQueue = queue.get(printer);
		}

		printerQueue.add(file);

		return "Printing " + file + " on " + printer;

	}
}
