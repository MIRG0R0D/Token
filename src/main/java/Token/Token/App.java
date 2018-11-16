package Token.Token;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Hello world!
 *
 */
public class App 
{
    private static byte[] fileToSign;
    private static String password;
    private static String certAlias;
    private static String keyStoreTyp;
    private static String keystoreUrl;
    
    public static void main( String[] args ) throws IOException, OperatorCreationException, GeneralSecurityException, CMSException
    {
        //System.out.println( "Hello World!" );
        //fs.sign(file, keyStoreUrl, heslo, alias, keyStoreType);
        //fs.verify
        //fs.signwithUSB
        //fs.verify
        //fs.printByte("Hello world".getBytes());
        
        FileSignature fs = new FileSignature();
        fileToSign = Files.readAllBytes(new File("C:\\ForJava\\usb\\text.txt").toPath());
        
        password = "changeit";
        certAlias="root";
        keyStoreTyp = "PKCS12";
        keystoreUrl = "C:\\ForJava\\usb\\server.p12";
        fs.printByte(fileToSign);
        fs.printByte(fs.sign(fileToSign, keystoreUrl, password, certAlias, keyStoreTyp));
        
        
        
        
    }
    private byte[] loadFile(String url) {
        Path path = Paths.get(url);
        byte[] file = null;
        try {
            file = Files.readAllBytes(path);
        } catch (IOException e) {
            System.exit(0);
        }
        return file;
    }
}
