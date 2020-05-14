import java.net.*;
import java.io.*;
import java.util.*;
import java.nio.*;

public class SecureClient {

	//class variables
	String sentence = null;
	Socket clientSocket = null;
	Socket connectionSocket = null;
	DataOutputStream out = null;
	DataInputStream in = null;
    String cmd = "";


	//constructors
	SecureClient(){};
	SecureClient(Socket s){
		this.connectionSocket = s;
	}

	public static void main(String[] args) throws Exception {
		//establish connection
    	SecureClient client = new SecureClient();
    	client.clientMethod(args);

	}

	private void clientMethod(String args[]) throws Exception{
		int port = Integer.parseInt(args[0]);
		String msgByServer = "";
		// Instantiate CryptoHelper
		CryptoHelper crypto = new CryptoHelper();
		byte[] serverPublicKey;

		while(true) {
			//create a socket and connect to  ("127.0.0.1", <Port>);
			clientSocket = new Socket("127.0.0.1", port);
    		out = new DataOutputStream(clientSocket.getOutputStream());
    		in = new DataInputStream(clientSocket.getInputStream());
    		System.out.println("Connected...");

			// --- HANDSHAKE START
			sendToServer("HELLOxxx",0);

			// Receive from server
			byte[] received = getFromServer();
			int lenOfData = ByteBuffer.wrap(Arrays.copyOfRange(received, 8, 12)).getInt();
			
			// get the Certificate info
			byte[] cert = Arrays.copyOfRange(received, 12, 12+lenOfData);

			// Get necessary fields from the certificate
			byte[] signature = getSignature(cert);
			String ca = getCA(cert);
			serverPublicKey = getPK(cert);
		
			// VERIFICATION
			if (crypto.verifySignature(cert, signature, ca)) {
				System.out.println("VERIFICATION DONE.");
				break;
			}

			else {
				System.out.println("VERIFICATION FAILED.");
			}
		}

		// Create and send encrypted secret
		int secret = crypto.generateSecret();
		byte[] secretEncrypted = crypto.encryptSecretAsymmetric(secret, serverPublicKey);
		sendSECRET(secretEncrypted);
		// --- HANDSHAKE END
		//----------------------------------------------------------------------------------------
		// --- AUTHENTICATION START
		// Start encryption
		sendToServer("STARTENC",0);
		
		// Send encrypted authentication info
		byte[] authEncrypted = crypto.encryptSymmetric("bilkent cs421", secret);
		sendAUTH(authEncrypted);
		System.out.println("auth sent");
		
		// Receive authentication response
		byte[] responseOfAuth = getFromServer();
		int lenOfData = ByteBuffer.wrap(Arrays.copyOfRange(responseOfAuth, 8, 12)).getInt();
		byte[] data = Arrays.copyOfRange(responseOfAuth, 12, 12+lenOfData);

		String response = crypto.decryptSymmetric(data, secret);
		System.out.println(response); // This should be "OK"

		// End encryption
		sendToServer("ENDENCxx",0);
		// --- AUTHENTICATION END
		//----------------------------------------------------------------------------------------
		// --- VIEW PUBLIC POSTS START
		sendToServer("PUBLICxx",0);

		byte[] responseForPublicPost = getFromServer();
		
		// Decode the byte array into a string & display
		String decodedResponse = decodeUS_ASCII(responseForPublicPost);
		
		// Display response on console
		System.out.println(decodedResponse);
		// --- VIEW PUBLIC POSTS END
		//----------------------------------------------------------------------------------------
		// --- VIEW PRIVATE MESSAGES START
		// Start encryption
		sendToServer("STARTENC",0);

		sendToServer("PRIVATEx",0);
		
		// Receive, decrypt & display
		byte[] responseOfPrivMsg = getFromServer();

		lenOfData = ByteBuffer.wrap(Arrays.copyOfRange(responseOfPrivMsg, 8, 12)).getInt();
		byte[] dataOfPrivMsg = Arrays.copyOfRange(responseOfPrivMsg, 12, 12+lenOfData);

		String decryptedPrivMsg = crypto.decryptSymmetric(dataOfPrivMsg, secret);
		System.out.println(decryptedPrivMsg);
		
		// End encryption
		sendToServer("ENDENCxx",0);
		// --- VIEW PRIVATE MESSAGES END
		//----------------------------------------------------------------------------------------
		// LOGOUT
		sendToServer("LOGOUTxx",0);
		
		//close the socket;
		clientSocket.close();
	
	}

	//logic to send commands to Server
    private void sendToServer(String command, int len) throws IOException{
    	try{
    		BufferedReader buffReader = new BufferedReader(new InputStreamReader(System.in));

    		byte[] bytearr = command.getBytes();
    		byte[] bytearr_len = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(len).array();

    		clientSocket.getOutputStream().write(bytearr);
    		clientSocket.getOutputStream().write(bytearr_len);
    		clientSocket.getOutputStream().flush();
    	}
    	catch(IOException ioexc){
        	ioexc.printStackTrace();
    	}
    }

    //logic to receive message from Server
    private byte[] getFromServer() throws IOException{
    	byte[] messageFromServer = new byte[1024];
    	clientSocket.getInputStream().read(messageFromServer);
    	return messageFromServer;
    }

    //method to get signature of certificate
    private byte[] getSignature(byte[] cert) {
    	String cert_s = new String(cert);
		String prefix = "SIGNATURE=";
		return Arrays.copyOfRange(cert, cert_s.indexOf(prefix) + prefix.length(), 
									cert_s.indexOf(prefix) + prefix.length() + 8);
    }

    //method to get ca of certificate
    private String getCA(byte[] cert) {
    	String cert_s = new String(cert);

		String prefix = "SIGNATURE=";
		String prefix2 = "CA=";

		byte[] ca_arr = Arrays.copyOfRange(cert, cert_s.indexOf(prefix2) + prefix2.length(), 
									cert_s.indexOf(prefix));
		String cert_ca = new String(ca_arr);
		return cert_ca;
    }

    //method to get pk of certificate
    private byte[] getPK(byte[] cert) {
    	String cert_s = new String(cert);

		String prefix = "PK=";

		byte[] pk_arr = Arrays.copyOfRange(cert, cert_s.indexOf(prefix) + prefix.length(), 
									cert_s.indexOf(prefix) + prefix.length() + 8);
		return pk_arr;
    }

    private void sendSECRET(byte[] secretEncrypted) throws IOException{
    	try{
    		BufferedReader buffReader = new BufferedReader(new InputStreamReader(System.in));

    		// length part 
    		int lenOfData = secretEncrypted.length;
    		byte[] bytearr_len = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(lenOfData).array();
    		byte[] bytearr = "SECRETxx".getBytes();

    		clientSocket.getOutputStream().write(bytearr);
    		clientSocket.getOutputStream().write(bytearr_len);
    		clientSocket.getOutputStream().write(secretEncrypted);
    		clientSocket.getOutputStream().flush();
    	}
    	catch(IOException ioexc){
        	ioexc.printStackTrace();
    	}
    }

    private void sendAUTH(byte[] authEncrypted) throws IOException{
    	try{
    		BufferedReader buffReader = new BufferedReader(new InputStreamReader(System.in));

    		// length part 
    		int lenOfData = authEncrypted.length;
    		byte[] bytearr_len = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(lenOfData).array();
    		byte[] bytearr = "AUTHxxxx".getBytes();

    		clientSocket.getOutputStream().write(bytearr);
    		clientSocket.getOutputStream().write(bytearr_len);
    		clientSocket.getOutputStream().write(authEncrypted);
    		clientSocket.getOutputStream().flush();
    	}
    	catch(IOException ioexc){
        	ioexc.printStackTrace();
    	}
    }

    private String decodeUS_ASCII(byte[] data) {
    	int lenOfData = ByteBuffer.wrap(Arrays.copyOfRange(data, 8, 12)).getInt();
		byte[] dataPart = Arrays.copyOfRange(data, 12, 12+lenOfData);

		String decoded = new String(dataPart);
		return decoded;
    }
}
