import java.io.*;
import java.net.Socket;
import java.security.*;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.util.logging.*;

public class SSHClient {
    private static final Logger logger = Logger.getLogger("SSHClient");

    public static void main(String[] args) {
        String serverAddress = "localhost";
        int serverPort = 2222;
        String username = "admin";
        String password = "admin123";

        if (args.length > 0) {
            serverAddress = args[0];
        }
        if (args.length > 1) {
            try {
                serverPort = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                logger.severe("Porti i dhënë nuk është numër i vlefshëm. Duke përdorur portin default: 2222.");
            }
        }
        if (args.length > 2) {
            username = args[2];
        }
        if (args.length > 3) {
            password = args[3];
        }

        if (args.length == 0) {
            logger.info("Duke përdorur vlerat default: localhost 2222 admin admin123");
            logger.info("Përdorimi: java SSHClient <adresa_serverit> <porti> <përdoruesi> <fjalëkalimi>");
        } else {
            logger.info(String.format("Duke përdorur: Server=%s, Port=%d, Përdorues=%s", serverAddress, serverPort,
                    username));
        }

        try {
            Logger.getLogger("").getHandlers()[0].setLevel(Level.ALL);
            logger.setLevel(Level.ALL);

            Socket socket = new Socket(serverAddress, serverPort);
            logger.info(String.format("🔌 Lidhja me serverin %s:%d u bë me sukses.", serverAddress, serverPort));

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
                    + "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
                    + "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
                    + "7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16);
            BigInteger g = BigInteger.valueOf(2);
            DHParameterSpec dhSpec = new DHParameterSpec(p, g);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhSpec);
            KeyPair keyPair = keyGen.generateKeyPair();

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Gabim gjatë ekzekutimit", e);
        }
    }
}