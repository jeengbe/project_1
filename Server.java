import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class Server implements Runnable {
  private ServerSocket serverSocket = null;
  private static int numConnectedClients = 0;

  public static void main(String args[]) throws Exception {
    System.out.println("\nServer Started\n");

    int port = -1;
    if (args.length >= 1) {
      port = Integer.parseInt(args[0]);
    }

    String type = "TLSv1.2";

    ServerSocketFactory ssf = getServerSocketFactory(type);
    ServerSocket ss = ssf.createServerSocket(port, 0, InetAddress.getByName(null));
    ((SSLServerSocket) ss).setNeedClientAuth(true); // enables client authentication

    new Server(ss);
  }

  public Server(ServerSocket ss) throws IOException {
    serverSocket = ss;

    newListener();
  }

  private void newListener() {
    (new Thread(this)).start();
  }

  public void run() {
    try {
      SSLSocket socket = (SSLSocket) serverSocket.accept();

      newListener();

      SSLSession session = socket.getSession();
      Certificate[] cert = session.getPeerCertificates();
      String subject = ((X509Certificate) cert[0]).getSubjectX500Principal().getName();

      numConnectedClients++;

      System.out.println("client connected");
      System.out.println("client name (cert subject DN field): " + subject);
      System.out.println(numConnectedClients + " concurrent connection(s)\n");

      PrintWriter out = null;
      BufferedReader in = null;

      out = new PrintWriter(socket.getOutputStream(), true);
      in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

      try {
        String clientMsg = null;
        while ((clientMsg = in.readLine()) != null) {
          String rev = new StringBuilder(clientMsg).reverse().toString();
          System.out.println("received '" + clientMsg + "' from client");
          System.out.print("sending '" + rev + "' to client...");
          out.println(rev);
          out.flush();
          System.out.println("done\n");
        }
      } finally {
        numConnectedClients--;
        in.close();
        out.close();
        socket.close();
      }

      System.out.println("client disconnected");
      System.out.println(numConnectedClients + " concurrent connection(s)\n");
    } catch (IOException e) {
      System.out.println("Client died: " + e.getMessage());
      e.printStackTrace();
    }
  }

  private static ServerSocketFactory getServerSocketFactory(String type) throws Exception {
    if (type.equals("TLSv1.2")) {
      char[] password = "password".toCharArray();
      SSLContext ctx = SSLContext.getInstance("TLSv1.2");

      KeyStore ks = KeyStore.getInstance("JKS");
      KeyStore ts = KeyStore.getInstance("JKS");
      KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
      TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");

      // keystore password (storepass)
      ks.load(new FileInputStream("serverkeystore"), password);
      // truststore password (storepass)
      ts.load(new FileInputStream("servertruststore"), password);

      kmf.init(ks, password); // certificate password (keypass)
      tmf.init(ts);

      ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

      return ctx.getServerSocketFactory();
    }

    return ServerSocketFactory.getDefault();
  }
}
