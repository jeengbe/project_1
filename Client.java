import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class Client {
  public static void main(String[] args) throws Exception {
    String host = null;
    int port = -1;

    for (int i = 0; i < args.length; i++) {
      System.out.println("args[" + i + "] = " + args[i]);
    }

    if (args.length < 1) {
      System.out.println("USAGE: java client [host] <port>");
      System.exit(-1);
    }

    try {
      if (args.length == 1)
        port = Integer.parseInt(args[0]);
      else {
        host = args[0];
        port = Integer.parseInt(args[1]);
      }
    } catch (IllegalArgumentException e) {
      System.out.println("USAGE: java client [host] <port>");
      System.exit(-1);
    }

    char[] password = "password".toCharArray();

    KeyStore ks = KeyStore.getInstance("JKS");
    KeyStore ts = KeyStore.getInstance("JKS");
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");

    SSLContext ctx = SSLContext.getInstance("TLSv1.2");

    // keystore password (storepass)
    ks.load(new FileInputStream("clientkeystore"), password);
    // truststore password (storepass)
    ts.load(new FileInputStream("clienttruststore"), password);

    kmf.init(ks, password); // user password (keypass)
    tmf.init(ts);

    ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

    SSLSocketFactory factory = ctx.getSocketFactory();

    SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
    System.out.println("\nsocket before handshake:\n" + socket + "\n");

    socket.startHandshake();

    SSLSession session = socket.getSession();

    Certificate[] cert = session.getPeerCertificates();
    String subject = ((X509Certificate) cert[0]).getSubjectX500Principal().getName();

    System.out.println("certificate name (subject DN field) on certificate received from server:\n" + subject + "\n");
    System.out.println("socket after handshake:\n" + socket + "\n");
    System.out.println("secure connection established\n\n");

    BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

    try {
      for (;;) {
        System.out.print(">");

        String msg = read.readLine();
        if (msg.equalsIgnoreCase("quit")) {
          break;
        }

        System.out.print("sending '" + msg + "' to server...");

        out.println(msg);
        out.flush();

        System.out.println("done");
        System.out.println("received '" + in.readLine() + "' from server\n");
      }

    } finally {
      in.close();
      out.close();
      read.close();
      socket.close();
    }
  }
}
