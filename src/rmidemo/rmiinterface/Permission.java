package rmidemo.rmiinterface;

import java.io.Serializable;

public class Permission implements Serializable {
private int PermmisionID;
private String PermmisionName;

public Permission(int serviceID,String serviceName) {
	this.PermmisionID = serviceID;
	this.PermmisionName = serviceName;
}

public int getServiceID() {
	return PermmisionID;
}
public void setServiceID(int serviceID) {
	this.PermmisionID = serviceID;
}
public String getServiceName() {
	return PermmisionName;
}
public void setServiceName(String serviceName) {
	this.PermmisionName = serviceName;
}
}
