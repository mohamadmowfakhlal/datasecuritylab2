package rmidemo.rmiinterface;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.UUID;

import javax.crypto.NoSuchPaddingException;

public interface PrintingInterface extends Remote {

    public UUID login(Login login) throws NoSuchPaddingException, Exception; // Creates a user session and returns the unique session identifier
    public boolean isLoggedIn(String username) throws RemoteException; // Checks whether a user has an associated, valid session identifier
    //public String print(byte[] filename, byte [] printer, UUID session) throws RemoteException, NoSuchPaddingException, Exception;   // prints file filename on the specified printer
    public String queue(String printer, UUID session) throws RemoteException,Exception, ClassNotFoundException, IOException;   // lists the print queue on the user's display in lines of the form <job number>   <file name>
    public String topQueue(String printer, int job, UUID session) throws RemoteException;   // moves job to the top of the queue
    public String start(UUID session) throws RemoteException;   // starts the print server
    public String stop(UUID session) throws RemoteException;   // stops the print server
    public String restart(UUID session) throws RemoteException;   // stops the print server, clears the print queue and starts the print server again
    public String status(String printer, UUID session) throws RemoteException;  // prints status of printer on the user's display
    public String readConfig(String parameter, UUID session) throws RemoteException;   // prints the value of the parameter on the user's display
    public String setConfig(String parameter, String value, UUID session) throws RemoteException;   // sets the parameter to value
    public byte[]  initDiffeHillmenServer(byte[] publickey) throws RemoteException, Exception;
    public String print(Printing print,UUID session) throws NoSuchPaddingException, Exception;
	public void initSymmetricConnection(byte[] encodedParams) throws NoSuchPaddingException, Exception;
	public void register(Registeration registration)throws NoSuchPaddingException, Exception;
}
