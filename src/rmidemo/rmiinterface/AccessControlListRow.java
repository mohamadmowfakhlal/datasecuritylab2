package rmidemo.rmiinterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class AccessControlListRow implements Serializable{
private String user;
private List<String> permissions = null;

public List<String>  getPermissions() {
	return permissions;
}

public void setPermissions(List<String> permissions) {
	this.permissions = permissions;
}

public AccessControlListRow(String user, List<String> permissions) {
	this.setUser(user);
	this.permissions = permissions;
}

public String getUser() {
	return user;
}

public void setUser(String user) {
	this.user = user;
}

}
