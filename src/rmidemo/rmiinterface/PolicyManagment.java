package rmidemo.rmiinterface;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PolicyManagment {
/*
	public static void createPermmison() {
		try {
			FileOutputStream fileOut = new FileOutputStream("permission.txt", true);
			ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
			Permission startpermission = new Permission(0,"start");
			objectOut.writeObject(startpermission);
			Permission stoppermission = new Permission(1,"stop");
			objectOut.writeObject(stoppermission);
			Permission restartpermission = new Permission(2,"restart");
			objectOut.writeObject(restartpermission);
			Permission readConpermission = new Permission(3,"readConfig");
			objectOut.writeObject(readConpermission);
			Permission writeConpermission = new Permission(4,"setConfig");
			objectOut.writeObject(writeConpermission);
			Permission printpermission = new Permission(5,"print");
			objectOut.writeObject(printpermission);
			Permission queuepermission = new Permission(6,"queue");
			objectOut.writeObject(queuepermission);
			Permission topQueuepermission = new Permission(7,"topQueue");
			objectOut.writeObject(topQueuepermission);
			Permission statuspermission = new Permission(8,"status");
			objectOut.writeObject(statuspermission);
			objectOut.close();
			fileOut.close();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
*/	
	public static void createPolicy() throws Exception {
		FileOutputStream fileOut = new FileOutputStream("policy.txt", true);
		ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);

		List<String>  fullPower = new ArrayList<String>(Arrays.asList("start","stop","restart","readConfig","setConfig","print","queue","topQueue","status"));
		PolicyRow fullPowerPer = new PolicyRow("fullpower",fullPower);
		objectOut.writeObject(fullPowerPer);
		
		List<String>  powerUser = new ArrayList<String>(Arrays.asList("print","queue","topQueue"));
		PolicyRow powerUserPer = new PolicyRow("powerUser",powerUser);
		objectOut.writeObject(powerUserPer);

		
		List<String>  technicain = new ArrayList<String>(Arrays.asList("start","stop","restart","readConfig","setConfig"));
		PolicyRow technicainPer = new PolicyRow("technicain",technicain);
		objectOut.writeObject(technicainPer);
		
		
		List<String>  normalUser = new ArrayList<String>(Arrays.asList("print","status"));
		PolicyRow normalUserPer = new PolicyRow("normaluser",normalUser);
		objectOut.writeObject(normalUserPer);

	}

	public static List<String> getPermmsionForRole(String roleName) throws FileNotFoundException, IOException, ClassNotFoundException {
		PolicyRow pr1;
		FileInputStream fi = new FileInputStream(new File("policy.txt"));
		ObjectInputStream oi = new ObjectInputStream(fi);
		while (true) {
			try {
				pr1 = (PolicyRow) oi.readObject();
				if (pr1.getRole().equals(roleName)) {
					fi.close();
					oi.close();
					return pr1.getPermissions();
				}

			} catch (EOFException e) {
				fi.close();
				oi.close();
				return null;
			}

		}
	}
}
