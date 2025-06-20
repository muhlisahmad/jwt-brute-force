import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JwtBruteForce {
  private static String candidate = "";
  private static long startTime = 0;
  private static final char[] CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=[]{};:'\",.<>?/\\|`~".toCharArray();

  public static void main(String[] args) throws Exception {
    Scanner sc = new Scanner(System.in);
    System.out.print("Enter JWT token\t\t\t: ");
    String jwt = sc.nextLine().trim();

    System.out.print("Enter max secret length to try\t: ");
    int maxLength = Integer.parseInt(sc.nextLine().trim());
    sc.close();

    String[] parts = jwt.split("\\.");
    if (parts.length != 3) {
      System.out.println("Invalid JWT format.");
      return;
    }

    String headerB64 = parts[0];
    String payloadB64 = parts[1];
    String signatureB64 = parts[2];

    String headerJson = new String(Base64.getUrlDecoder().decode(headerB64), StandardCharsets.UTF_8);
    String alg = extractAlgFromHeader(headerJson);
    if (alg == null) {
      System.out.println("Failed to extract alg from header.");
      return;
    }

    String javaAlg = switch (alg) {
      case "HS256" -> "HmacSHA256";
      case "HS384" -> "HmacSHA384";
      case "HS512" -> "HmacSHA512";
      default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
    };

    String signingInput = headerB64 + "." + payloadB64;

    startTime = System.nanoTime();

    for (int length = 1; length <= maxLength; length++) {
      if (bruteForce(signingInput, signatureB64, javaAlg, new char[length], 0, startTime)) {
        double total = (System.nanoTime() - startTime) / 1e9;
        System.out.printf("\n✅ Found secret!\t: %-30s Total time\t: %.2f seconds%n", candidate, total);
        return;
      }
    }

    double total = (System.nanoTime() - startTime) / 1e9;
    System.out.printf("\n❌ Secret not found. Total time: %.2f seconds%n", total);
  }

  private static boolean bruteForce(String signingInput, String targetSig, String alg, char[] current, int pos, long startTime) throws Exception {
    long elapsed = System.nanoTime() - startTime;
    long millis = elapsed / 1_000_000;
    long hundredths = (millis % 1000) / 10;
    long seconds = (millis / 1000) % 60;
    long minutes = (millis / (1000 * 60)) % 60;
    long hours = (millis / (1000 * 60 * 60));

    System.out.printf("⏱  Trying\t\t: %-30s Time elapsed\t: %03d:%02d:%02d.%02d\r", candidate, hours, minutes, seconds, hundredths);

    if (pos == current.length) {
      candidate = new String(current);
      String testSig = hmacBase64Url(signingInput, candidate, alg);
      return testSig.equals(targetSig);
    }

    for (char c : CHARSET) {
      current[pos] = c;
      if (bruteForce(signingInput, targetSig, alg, current, pos + 1, startTime)) {
        return true;
      }
    }

    return false;
  }

  private static String extractAlgFromHeader(String headerJson) {
    int algIndex = headerJson.indexOf("\"alg\"");
    if (algIndex == -1) return null;

    int colon = headerJson.indexOf(':', algIndex);
    int quote1 = headerJson.indexOf('"', colon + 1);
    int quote2 = headerJson.indexOf('"', quote1 + 1);
    return headerJson.substring(quote1 + 1, quote2);
  }

  private static String hmacBase64Url(String data, String key, String algorithm) throws Exception {
    Mac mac = Mac.getInstance(algorithm);
    SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), algorithm);
    mac.init(secretKey);
    byte[] hmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(hmac);
  }
}
