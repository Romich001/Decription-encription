package profects.encryptionDecryption;


import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {

    public static void main(String[] args) {
        new DataManager(args);
    }
}

class DataManager{
    String result = "";
    Cypher cypher;
    String mode = "";
    int key = 0;
    String data = "";
    String inPath = "";
    String outPath = "";
    String alg = "shift";

    public DataManager(String[] args){
        getParameters(args);
        setMethod();
        doChanges();
        getPutOut();
    }

    private void getParameters(String[] args){
        for(int i = 0; i < args.length; i = i+2){
            String parameter = args[i];
            if("-mode".equals(parameter)){
                mode = args[i + 1];
            }else if("-data".equals(parameter)){
                data = args[i +1];
            }else if("-key".equals(parameter)){
                key = Integer.parseInt(args[i+1]);
            }else if("-in".equals(parameter)) {
                inPath = args[i + 1];
            }else if("-out".equals(parameter)) {
                outPath = args[i + 1];
            }else if ("-alg".equals(parameter)){
                alg = args[i + 1];
            }
        }
        if(data.isEmpty() && !inPath.isEmpty()){
            try{
                data = new String (Files.readAllBytes(Paths.get(inPath)));
            }catch (IOException e) {
                System.out.println("Error " + e.getMessage());
            }
        }
    }

    private void setMethod() {
        if("unicode".equals(alg)){
            cypher = new UnicodeCypher();
        }else {
            cypher = new ShiftCypher();
        }
    }

    private void doChanges(){
        if("dec".equals(mode)){
            result = cypher.decryption(data, key);
        }
        else if("enc".equals(mode)){
            result =cypher.encryption(data, key);
        }
    }

    private void getPutOut(){
        if(inPath.isEmpty()){
            System.out.println(result);
        }else{
            File outPut = new File(outPath);
            try(FileWriter writer = new FileWriter(outPut)){
                writer.write(result);
            }catch (IOException e){
                System.out.println("Error " + e.getMessage() );
            }
        }
    }
}

interface Cypher{

    String encryption(String data, int key);
    String decryption(String data, int key);
}

class UnicodeCypher implements Cypher {

    @Override
    public String encryption(String data, int key) {
        String encrStr = "";
        for(int i = 0; i < data.length(); i++){
            char currentChar = data.charAt(i);
            currentChar += key;
            encrStr += currentChar;

        }
        return encrStr;
    }

    @Override
    public String decryption(String data, int key) {
        String decrStr = "";
        for(int i = 0; i < data.length(); i++){
            char currentChar = data.charAt(i);
            currentChar -= key;
            decrStr += currentChar;
        }
        return decrStr;
    }
}

class ShiftCypher implements Cypher {

    @Override
    public String encryption(String data, int key) {
        String encrStr = "";
        for(int i = 0; i < data.length(); i++){
            char ch = data.charAt(i);
            if(ch >= 'a' && ch <= 'z' ){
                ch += key;
                if(ch > 'z'){
                    ch -= 26;
                }
            }else if(ch >= 'A' && ch <= 'Z'){
                ch += key;
                if(ch > 'Z'){
                    ch -= 26;
                }
            }
            encrStr += ch;
        }
        return encrStr;
    }

    @Override
    public String decryption(String data, int key) {
        String decrStr = "";
        for(int i = 0; i < data.length(); i++){
            char ch = data.charAt(i);
            if(ch >= 'a' && ch <= 'z'){
                ch -= key;
                if(ch < 'a'){
                    ch += 26;
                }
            }else if(ch >= 'A' && ch <= 'Z'){
                ch -= key;
                if(ch < 'A'){
                    ch += 26;
                }
            }
            decrStr += ch;
        }
        return decrStr;
    }
}
