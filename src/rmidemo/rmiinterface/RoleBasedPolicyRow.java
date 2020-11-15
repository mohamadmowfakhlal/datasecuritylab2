package rmidemo.rmiinterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class RoleBasedPolicyRow implements Serializable{
private String role;
private List<String> permissions = null;

public List<String>  getPermissions() {
	return permissions;
}

public void setPermissions(List<String> permissions) {
	this.permissions = permissions;
}

public RoleBasedPolicyRow(String role, List<String> permissions) {
	this.setRole(role);
	this.permissions = permissions;
}

public String getRole() {
	return role;
}

public void setRole(String role) {
	this.role = role;
}

}
