package Token.Token;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        System.out.println( "Hello F*@#$ World!" );
        FileSignature fs = new FileSignature();
        //fs.sign(file, keyStoreUrl, heslo, alias, keyStoreType);
        //fs.verify
        //fs.signwithUSB
        //fs.verify
        
        
        
        
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
