import java.math.BigInteger;
import java.util.Random;

public class RSA {

    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger n;

    
    //Constructor to generate RSA keys 
    public RSA(int bitLength) {
        generateKeys(bitLength);
    }

    
    // Generate RSA keys

    private void generateKeys(int bitLength) {
        Random rand = new Random();
        BigInteger p, q;

        
        // Choice between two random prime numbers p and q 

        p = BigInteger.probablePrime(bitLength, rand);
        q = BigInteger.probablePrime(bitLength, rand);

        
        // Calculate n = p * q 
        n = p.multiply(q);

        
        // Calculate the Eulerian function phi(n
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        
        // Choose a public key such as 1 < e < phi and gcd(e, phi) = 1
        do {
            publicKey = new BigInteger(bitLength, rand);
        } while (publicKey.compareTo(BigInteger.ONE) <= 0 || publicKey.compareTo(phi) >= 0 || publicKey.gcd(phi).compareTo(BigInteger.ONE) != 0);

        
        // Calculate the private key such as (d * e) % phi = 1
        privateKey = publicKey.modInverse(phi);
    }

    // RSA Cypher 
    public BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, n);
    }

    // RSA Decypher
    public BigInteger decrypt(BigInteger ciphertext) {
        return ciphertext.modPow(privateKey, n);
    }

    public static void main(String[] args) {
        RSA rsa = new RSA(1024); // Générer des clés de 1024 bits

        
        // The text to cypher 
        BigInteger message = new BigInteger("42");

        
        // Cypher 
        BigInteger ciphertext = rsa.encrypt(message);

        System.out.println("Message original: " + message);
        System.out.println("Message chiffré: " + ciphertext);

        
        // Decypher 

        BigInteger decryptedMessage = rsa.decrypt(ciphertext);
        System.out.println("Message déchiffré: " + decryptedMessage);
    }
}
