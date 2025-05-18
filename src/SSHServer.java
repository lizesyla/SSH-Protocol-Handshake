import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.util.logging.*;

public class SSHServer {
    private static final Logger logger = Logger.getLogger("SSHServer");

    private static int port = 2222;
    private static int rsaKeySize = 2048;
    private static String username = "admin";
    private static String password = "admin123";
    private static String dhPHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
            + "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
            + "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
            + "7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF";
    private static BigInteger dhG = BigInteger.valueOf(2);

    private static void printHelp() {
        System.out.println("SSHServer Usage:");
        System.out.println("  java SSHServer [options]");
        System.out.println("\nOptions:");
        System.out.println("  --port <port_number>       Set the server port (default: " + port + ")");
        System.out.println("  --rsa-keysize <size>       Set RSA key size (default: " + rsaKeySize + ")");
        System.out.println("  --user <username>          Set the username for authentication (default: \"" + username + "\")");
        System.out.println("  --pass <password>          Set the password for authentication (default: \"" + password + "\")");
        System.out.println("                             WARNING: Passing password via CLI is insecure.");
        System.out.println("  --dh-p <hex_string>        Set the Diffie-Hellman prime modulus (P) in hex.");
        System.out.println("  --dh-g <integer>           Set the Diffie-Hellman generator (G).");
        System.out.println("  --help                     Show this help message and exit.");
        System.out.println("\nExample DH P:");
        System.out.println("  " + dhPHex);
        System.out.println("Example DH G:");
        System.out.println("  " + dhG.toString());
    }

    private static void parseArguments(String[] args) {
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--port":
                    if (i + 1 < args.length) {
                        try {
                            port = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            logger.severe("Invalid port number: " + args[i]);
                            System.exit(1);
                        }
                    } else {
                        logger.severe("Missing value for --port");
                        System.exit(1);
                    }
                    break;
                case "--rsa-keysize":
                    if (i + 1 < args.length) {
                        try {
                            rsaKeySize = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            logger.severe("Invalid RSA key size: " + args[i]);
                            System.exit(1);
                        }
                    } else {
                        logger.severe("Missing value for --rsa-keysize");
                        System.exit(1);
                    }
                    break;
                case "--user":
                    if (i + 1 < args.length) {
                        username = args[++i];
                    } else {
                        logger.severe("Missing value for --user");
                        System.exit(1);
                    }
                    break;
                case "--pass":
                    if (i + 1 < args.length) {
                        password = args[++i];
                    } else {
                        logger.severe("Missing value for --pass");
                        System.exit(1);
                    }
                    break;
                case "--dh-p":
                    if (i + 1 < args.length) {
                        dhPHex = args[++i];
                    } else {
                        logger.severe("Missing value for --dh-p");
                        System.exit(1);
                    }
                    break;
                case "--dh-g":
                    if (i + 1 < args.length) {
                        try {
                            dhG = new BigInteger(args[++i]);
                        } catch (NumberFormatException e) {
                            logger.severe("Invalid DH generator G: " + args[i]);
                            System.exit(1);
                        }
                    } else {
                        logger.severe("Missing value for --dh-g");
                        System.exit(1);
                    }
                    break;
                case "--help":
                case "-h":
                    printHelp();
                    System.exit(0);
                    break;
                default:
                    logger.warning("Unknown argument: " + arg);
                    printHelp();
                    System.exit(1);
            }
        }
    }

    public static void main(String[] args) {
        try {
            Logger.getLogger("").getHandlers()[0].setLevel(Level.ALL);
            logger.setLevel(Level.ALL);

            parseArguments(args);

            logger.info("Starting SSH Server with configuration:");
            logger.info("  Port: " + port);
            logger.info("  RSA Key Size: " + rsaKeySize);
            logger.info("  Username: " + username);
            logger.info("  DH P (first 32 hex chars): " + (dhPHex.length() > 32 ? dhPHex.substring(0,32) + "..." : dhPHex) );
            logger.info("  DH G: " + dhG.toString());


            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
            rsaKeyGen.initialize(rsaKeySize);
            KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();

            ServerSocket serverSocket = new ServerSocket(port); // Use configured port
            logger.info("SSH Server i nisur. Duke pritur lidhje nga klienti ne portin " + port + "...");

            Socket client = serverSocket.accept();
            logger.info("Klienti u lidh nga: " + client.getRemoteSocketAddress());

            DataInputStream in = new DataInputStream(client.getInputStream());
            DataOutputStream out = new DataOutputStream(client.getOutputStream());

            BigInteger p = new BigInteger(dhPHex, 16);
            DHParameterSpec dhSpec = new DHParameterSpec(p, dhG);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhSpec);
            KeyPair dhKeyPair = keyGen.generateKeyPair();

            byte[] dhPublicKeyEnc = dhKeyPair.getPublic().getEncoded();

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(rsaKeyPair.getPrivate());
            sig.update(dhPublicKeyEnc);
            byte[] signature = sig.sign();

            out.writeInt(dhPublicKeyEnc.length);
            out.write(dhPublicKeyEnc);

            out.writeInt(signature.length);
            out.write(signature);

            byte[] rsaPubKeyEnc = rsaKeyPair.getPublic().getEncoded();
            out.writeInt(rsaPubKeyEnc.length);
            out.write(rsaPubKeyEnc);

            int clientKeyLen = in.readInt();
            byte[] clientPubKeyEnc = new byte[clientKeyLen];
            in.readFully(clientPubKeyEnc);

            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey clientPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(clientPubKeyEnc));

            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(dhKeyPair.getPrivate());
            ka.doPhase(clientPubKey, true);
            byte[] sharedSecret = ka.generateSecret();

            logger.info("🔑 Shared Secret u krijua me sukses.");

            String clientUsername = in.readUTF();
            String clientPassword = in.readUTF();
            logger.info("Kredencialet u moren: " + clientUsername);

            boolean authSuccess = clientUsername.equals(username) && clientPassword.equals(password);
            out.writeBoolean(authSuccess);
            logger.info(authSuccess ? "Autentikimi i suksesshem." : "Gabim ne autentikim.");

            client.close();
            serverSocket.close();
            logger.info("Serveri u mbyll.");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Gabim ne server", e);
            System.exit(1);
        }
    }
}
