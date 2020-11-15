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
	public static void createRoleBasedAccessControl() throws Exception {
		FileOutputStream fileOut = new FileOutputStream("policy.txt", true);
		ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);

		List<String>  fullPower = new ArrayList<String>(Arrays.asList("start","stop","restart","readConfig","setConfig","print","queue","topQueue","status"));
		RoleBasedPolicyRow fullPowerPer = new RoleBasedPolicyRow("fullpower",fullPower);
		objectOut.writeObject(fullPowerPer);
		
		List<String>  powerUser = new ArrayList<String>(Arrays.asList("restart","queue","topQueue"));
		RoleBasedPolicyRow powerUserPer = new RoleBasedPolicyRow("powerUser",powerUser);
		objectOut.writeObject(powerUserPer);

		
		List<String>  technicain = new ArrayList<String>(Arrays.asList("start","stop","restart","readConfig","setConfig","status"));
		RoleBasedPolicyRow technicainPer = new RoleBasedPolicyRow("technicain",technicain);
		objectOut.writeObject(technicainPer);
		
		
		List<String>  normalUser = new ArrayList<String>(Arrays.asList("print","queue"));
		RoleBasedPolicyRow normalUserPer = new RoleBasedPolicyRow("normaluser",normalUser);
		objectOut.writeObject(normalUserPer);
		objectOut.close();
		fileOut.close();

	}

	public static List<String> getPermmsionForRole(String roleName) throws FileNotFoundException, IOException, ClassNotFoundException {
		RoleBasedPolicyRow pr1;
		FileInputStream fi = new FileInputStream(new File("policy.txt"));
		ObjectInputStream oi = new ObjectInputStream(fi);
		while (true) {
			try {
				pr1 = (RoleBasedPolicyRow) oi.readObject();
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
	
	public static List<String> getPermssionForUser(String userName) throws FileNotFoundException, IOException, ClassNotFoundException {
		AccessControlListRow pr1;
		 File newFile = new File("AccessControlListPolicy.txt");

		    if (newFile.length() == 0)
		    	return null;

		FileInputStream fi = new FileInputStream(new File("AccessControlListPolicy.txt"));
		ObjectInputStream oi = new ObjectInputStream(fi);
		while (true) {
			try {
				pr1 = (AccessControlListRow) oi.readObject();
				if (pr1.getUser().equals(userName)) {
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
	
	public static void createAccessControlList() throws Exception{
		FileOutputStream fileOut = new FileOutputStream("AccessControlListPolicy.txt", true);
		ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
		
		List<String>  alicePermissions = new ArrayList<String>(Arrays.asList("start","stop","restart","readConfig","setConfig","print","queue","topQueue","status"));
		AccessControlListRow alice = new AccessControlListRow("Alice",alicePermissions);
		objectOut.writeObject(alice);
		
		List<String>  ceciliaPermssions = new ArrayList<String>(Arrays.asList("restart","queue","topQueue"));
		AccessControlListRow cecilia = new AccessControlListRow("Cecilia",ceciliaPermssions);
		objectOut.writeObject(cecilia);

		
		List<String>  bobPermissions = new ArrayList<String>(Arrays.asList("start","stop","restart","readConfig","setConfig","status"));
		AccessControlListRow bob = new AccessControlListRow("Bob",bobPermissions);
		objectOut.writeObject(bob);
		
		
		List<String>  davidPermssions = new ArrayList<String>(Arrays.asList("print","queue"));
		AccessControlListRow david = new AccessControlListRow("David",davidPermssions);
		objectOut.writeObject(david);
	
		List<String>  EricaPermssions = new ArrayList<String>(Arrays.asList("print","queue"));
		AccessControlListRow erica = new AccessControlListRow("Erica",EricaPermssions);
		objectOut.writeObject(erica);
		
		List<String>  fredPermssions = new ArrayList<String>(Arrays.asList("print","queue"));
		AccessControlListRow fred = new AccessControlListRow("Fred",fredPermssions);
		objectOut.writeObject(fred);
		
		List<String>  henryPermssions = new ArrayList<String>(Arrays.asList("print","queue"));
		AccessControlListRow henry = new AccessControlListRow("Henry",henryPermssions);
		objectOut.writeObject(henry);	objectOut.close();
		fileOut.close();
		
	}
}
