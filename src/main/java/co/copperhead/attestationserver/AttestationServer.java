package attestationserver;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

public class AttestationServer {
    private static final Path CHALLENGE_INDEX_PATH = Paths.get("challenge_index.bin");
    private static final File SAMPLES_DATABASE = new File("samples.db");

    private static byte[] challengeIndex;

    public static void main(final String[] args) throws Exception {
        final SQLiteConnection db = new SQLiteConnection(SAMPLES_DATABASE);
        db.open();
        db.exec("CREATE TABLE IF NOT EXISTS SAMPLES (SAMPLE TEXT NOT NULL)");
        db.dispose();

        try {
            challengeIndex = Files.readAllBytes(CHALLENGE_INDEX_PATH);
            if (challengeIndex.length != AttestationProtocol.CHALLENGE_LENGTH) {
                throw new RuntimeException("challenge index is not " + AttestationProtocol.CHALLENGE_LENGTH + " bytes");
            }
        } catch (final IOException e) {
            challengeIndex = AttestationProtocol.getChallenge();
            Files.write(CHALLENGE_INDEX_PATH, challengeIndex);
        }

        final HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 8080), 0);
        server.createContext("/submit", new SubmitHandler());
        server.createContext("/verify", new VerifyHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }

    private static class SubmitHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final InputStream input = exchange.getRequestBody();

                final ByteArrayOutputStream sample = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                    sample.write(buffer, 0, read);

                    if (sample.size() > 64 * 1024) {
                        final String response = "Sample too large\n";
                        exchange.sendResponseHeaders(400, response.length());
                        final OutputStream output = exchange.getResponseBody();
                        output.write(response.getBytes());
                        output.close();
                        return;
                    }
                }

                try {
                    final SQLiteConnection db = new SQLiteConnection(SAMPLES_DATABASE);
                    db.open();
                    SQLiteStatement st = db.prepare("INSERT INTO samples VALUES (?)");
                    st.bind(1, sample.toByteArray());
                    st.step();
                    st.dispose();
                    db.dispose();
                } catch (SQLiteException e) {
                    throw new IOException(e);
                }

                final String response = "Success\n";
                exchange.sendResponseHeaders(200, response.length());
                final OutputStream output = exchange.getResponseBody();
                output.write(response.getBytes());
                output.close();
            } else {
                final String response = "Invalid request\n";
                exchange.sendResponseHeaders(400, response.length());
                final OutputStream output = exchange.getResponseBody();
                output.write(response.getBytes());
                output.close();
            }
        }
    }

    private static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            final String method = exchange.getRequestMethod();

            if (method.equalsIgnoreCase("GET")) {
                // TODO: keep temporary state for active challenges to verify single use
                final byte[] challengeMessage = AttestationProtocol.getChallengeMessage(challengeIndex);
                exchange.sendResponseHeaders(200, challengeMessage.length);
                final OutputStream output = exchange.getResponseBody();
                output.write(challengeMessage);
                output.close();
            } else if (method.equalsIgnoreCase("POST")) {
                final InputStream input = exchange.getRequestBody();

                final ByteArrayOutputStream attestation = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                    attestation.write(buffer, 0, read);

                    if (attestation.size() > AttestationProtocol.MAX_MESSAGE_SIZE) {
                        final String response = "Attestation too large\n";
                        exchange.sendResponseHeaders(400, response.length());
                        final OutputStream output = exchange.getResponseBody();
                        output.write(response.getBytes());
                        output.close();
                        return;
                    }
                }

                final byte[] bytes = attestation.toByteArray();

                final String response = "Not implemented yet\n";
                exchange.sendResponseHeaders(501, response.length());
                final OutputStream output = exchange.getResponseBody();
                output.write(response.getBytes());
                output.close();
            } else {
                final String response = "Invalid request\n";
                exchange.sendResponseHeaders(400, response.length());
                final OutputStream output = exchange.getResponseBody();
                output.write(response.getBytes());
                output.close();
            }
        }
    }
}
