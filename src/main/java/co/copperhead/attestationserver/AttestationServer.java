package attestationserver;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.concurrent.Executors;
import java.util.zip.DataFormatException;

public class AttestationServer {
    private static final Path CHALLENGE_INDEX_PATH = Paths.get("challenge_index.bin");
    private static final File SAMPLES_DATABASE = new File("samples.db");
    private static final File ATTESTATION_DATABASE = new File("attestation.db");

    private static byte[] challengeIndex;

    public static void main(final String[] args) throws Exception {
        final SQLiteConnection samplesConn = new SQLiteConnection(SAMPLES_DATABASE);
        samplesConn.open();
        samplesConn.exec("CREATE TABLE IF NOT EXISTS SAMPLES (Sample TEXT NOT NULL)");
        samplesConn.dispose();

        final SQLiteConnection attestationConn = new SQLiteConnection(ATTESTATION_DATABASE);
        attestationConn.open();
        // TODO: pinned certificate chain
        attestationConn.exec("CREATE TABLE IF NOT EXISTS DEVICES (\n" +
            "pinned_certificate BLOB NOT NULL,\n" +
            "pinned_verified_boot_key BLOB NOT NULL,\n" +
            "pinned_os_stock INTEGER NOT NULL,\n" +
            "pinned_os_version INTEGER NOT NULL,\n" +
            "pinned_os_patch_level INTEGER NOT NULL,\n" +
            "pinned_app_version INTEGER NOT NULL,\n" +
            "verified_time_first INTEGER NOT NULL,\n" +
            "verified_time_last INTEGER NOT NULL\n" +
            ")");
        attestationConn.dispose();

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
                final byte[] buffer = new byte[4096];
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
                    final SQLiteConnection conn = new SQLiteConnection(SAMPLES_DATABASE);
                    conn.open();
                    SQLiteStatement st = conn.prepare("INSERT INTO samples VALUES (?)");
                    st.bind(1, sample.toByteArray());
                    st.step();
                    st.dispose();
                    conn.dispose();
                } catch (SQLiteException e) {
                    e.printStackTrace();
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
                final byte[] buffer = new byte[4096];
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

                final byte[] attestationResult = attestation.toByteArray();
                final byte[] challengeMessage = null;

                final SQLiteConnection conn = new SQLiteConnection(ATTESTATION_DATABASE);
                try {
                    conn.open();
                    conn.dispose();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    throw new IOException(e);
                }

                try {
                    AttestationProtocol.verifySerialized(attestationResult, challengeMessage);
                } catch (final DataFormatException | GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    throw new IOException(e);
                } catch (final BufferUnderflowException e) {
                    e.printStackTrace();
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
}
