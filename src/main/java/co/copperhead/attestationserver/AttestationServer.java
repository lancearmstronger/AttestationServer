package attestationserver;

import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import org.bouncycastle.crypto.generators.SCrypt;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.util.zip.DataFormatException;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;

import attestationserver.AttestationProtocol.DeviceInfo;

import static com.almworks.sqlite4java.SQLiteConstants.SQLITE_CONSTRAINT_UNIQUE;

import static attestationserver.AttestationProtocol.fingerprintsCopperheadOS;
import static attestationserver.AttestationProtocol.fingerprintsStock;

public class AttestationServer {
    private static final Path CHALLENGE_INDEX_PATH = Paths.get("challenge_index.bin");
    private static final File SAMPLES_DATABASE = new File("samples.db");
    private static final int DEFAULT_VERIFY_INTERVAL = 3600;
    private static final int BUSY_TIMEOUT = 10 * 1000;
    private static final int QR_CODE_SIZE = 300;
    private static final byte[] DEMO_SUBSCRIBE_KEY = new byte[32];
    private static final long SESSION_LENGTH = 1000 * 60 * 60 * 48;

    private static final Cache<ByteBuffer, Boolean> pendingChallenges = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.MINUTES)
            .maximumSize(100000)
            .build();
    private static byte[] challengeIndex;

    static void open(final SQLiteConnection conn, final boolean readOnly) throws SQLiteException {
        if (readOnly) {
            conn.openReadonly();
        } else {
            conn.open();
        }
        conn.setBusyTimeout(BUSY_TIMEOUT);
        conn.exec("PRAGMA foreign_keys=ON");
        conn.exec("PRAGMA journal_mode=WAL");
    }

    public static void main(final String[] args) throws Exception {
        final SQLiteConnection samplesConn = new SQLiteConnection(SAMPLES_DATABASE);
        try {
            open(samplesConn, false);
            samplesConn.exec("CREATE TABLE IF NOT EXISTS Samples (\n" +
                    "sample TEXT NOT NULL,\n" +
                    "time INTEGER NOT NULL\n" +
                    ")");
            samplesConn.exec("VACUUM");
        } finally {
            samplesConn.dispose();
        }

        final SQLiteConnection attestationConn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        try {
            open(attestationConn, false);
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Accounts (\n" +
                    "userId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n" +
                    "username TEXT UNIQUE NOT NULL,\n" +
                    "passwordHash BLOB NOT NULL,\n" +
                    "passwordSalt BLOB NOT NULL,\n" +
                    "subscribeKey BLOB NOT NULL,\n" +
                    "creationTime INTEGER NOT NULL,\n" +
                    "verifyInterval INTEGER NOT NULL DEFAULT 3600\n" +
                    ")");
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Sessions (\n" +
                    "sessionId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\n" +
                    "userId INTEGER NOT NULL REFERENCES Accounts (userId),\n" +
                    "cookieToken BLOB NOT NULL,\n" +
                    "requestToken BLOB NOT NULL,\n" +
                    "expiryTime INTEGER NOT NULL\n" +
                    ")");
            attestationConn.exec("CREATE INDEX IF NOT EXISTS Sessions_expiryTime " +
                    "ON Sessions (expiryTime)");
            attestationConn.exec("CREATE INDEX IF NOT EXISTS Sessions_userId " +
                    "ON Sessions (userId)");
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Devices (\n" +
                    "fingerprint BLOB PRIMARY KEY NOT NULL,\n" +
                    "pinnedCertificate0 BLOB NOT NULL,\n" +
                    "pinnedCertificate1 BLOB NOT NULL,\n" +
                    "pinnedCertificate2 BLOB NOT NULL,\n" +
                    "pinnedVerifiedBootKey BLOB NOT NULL,\n" +
                    "pinnedOsVersion INTEGER NOT NULL,\n" +
                    "pinnedOsPatchLevel INTEGER NOT NULL,\n" +
                    "pinnedAppVersion INTEGER NOT NULL,\n" +
                    "userProfileSecure INTEGER NOT NULL CHECK (userProfileSecure in (0, 1)),\n" +
                    "enrolledFingerprints INTEGER NOT NULL CHECK (enrolledFingerprints in (0, 1)),\n" +
                    "accessibility INTEGER NOT NULL CHECK (accessibility in (0, 1)),\n" +
                    "deviceAdmin INTEGER NOT NULL CHECK (deviceAdmin in (0, 1, 2)),\n" +
                    "adbEnabled INTEGER NOT NULL CHECK (adbEnabled in (0, 1)),\n" +
                    "addUsersWhenLocked INTEGER NOT NULL CHECK (addUsersWhenLocked in (0, 1)),\n" +
                    "denyNewUsb INTEGER NOT NULL CHECK (denyNewUsb in (0, 1)),\n" +
                    "verifiedTimeFirst INTEGER NOT NULL,\n" +
                    "verifiedTimeLast INTEGER NOT NULL,\n" +
                    "userId INTEGER REFERENCES Accounts (userId)\n" +
                    ")");
            attestationConn.exec("CREATE INDEX IF NOT EXISTS Devices_userId_verifiedTimeFirst " +
                    "ON Devices (userId, verifiedTimeFirst)");
            attestationConn.exec(
                    "CREATE TABLE IF NOT EXISTS Attestations (\n" +
                    "fingerprint BLOB NOT NULL REFERENCES Devices (fingerprint),\n" +
                    "time BLOB NOT NULL,\n" +
                    "strong INTEGER NOT NULL CHECK (strong in (0, 1)),\n" +
                    "teeEnforced TEXT NOT NULL,\n" +
                    "osEnforced TEXT NOT NULL\n" +
                    ")");
            attestationConn.exec("CREATE INDEX IF NOT EXISTS Attestations_fingerprint_time " +
                    "ON Attestations (fingerprint, time)");
            attestationConn.exec("VACUUM");
        } finally {
            attestationConn.dispose();
        }

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
        server.createContext("/create_account", new CreateAccountHandler());
        server.createContext("/login", new LoginHandler());
        server.createContext("/logout", new LogoutHandler());
        server.createContext("/logout_everywhere", new LogoutEverywhereHandler());
        server.createContext("/rotate", new RotateHandler());
        server.createContext("/account", new AccountHandler());
        server.createContext("/account.png", new AccountQrHandler());
        server.createContext("/configuration", new ConfigurationHandler());
        server.createContext("/devices.json", new DevicesHandler());
        server.createContext("/challenge", new ChallengeHandler());
        server.createContext("/verify", new VerifyHandler());
        server.setExecutor(new ThreadPoolExecutor(10, 100, 60, TimeUnit.SECONDS, new SynchronousQueue<Runnable>()));
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
                        final byte[] response = "Sample too large\n".getBytes();
                        exchange.sendResponseHeaders(400, response.length);
                        try (final OutputStream output = exchange.getResponseBody()) {
                            output.write(response);
                        }
                        return;
                    }
                }

                final SQLiteConnection conn = new SQLiteConnection(SAMPLES_DATABASE);
                try {
                    open(conn, false);
                    final SQLiteStatement insert = conn.prepare("INSERT INTO Samples VALUES (?, ?)");
                    insert.bind(1, sample.toByteArray());
                    insert.bind(2, System.currentTimeMillis());
                    insert.step();
                    insert.dispose();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    final byte[] response = "Failed to save data.\n".getBytes();
                    exchange.sendResponseHeaders(500, response.length);
                    try (final OutputStream output = exchange.getResponseBody()) {
                        output.write(response);
                    }
                    return;
                } finally {
                    conn.dispose();
                }

                exchange.sendResponseHeaders(200, -1);
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static byte[] hash(final byte[] password, final byte[] salt) {
        return SCrypt.generate(password, salt, 32768, 8, 1, 32);
    }

    private static void createAccount(final String username, final String password)
            throws GeneralSecurityException, SQLiteException {
        if (username.length() > 32 || !username.matches("[a-zA-Z0-9]+")) {
            throw new GeneralSecurityException("invalid username");
        }
        if (password.length() < 8 || password.length() > 4096) {
            throw new GeneralSecurityException("invalid password");
        }

        final SecureRandom random = new SecureRandom();
        final byte[] passwordSalt = new byte[32];
        random.nextBytes(passwordSalt);
        final byte[] passwordHash = hash(password.getBytes(), passwordSalt);
        final byte[] subscribeKey = new byte[32];
        random.nextBytes(subscribeKey);

        final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        try {
            open(conn, false);
            final SQLiteStatement insert = conn.prepare("INSERT INTO Accounts " +
                    "(username, passwordHash, passwordSalt, subscribeKey, creationTime) " +
                    "VALUES (?, ?, ?, ?, ?)");
            insert.bind(1, username);
            insert.bind(2, passwordHash);
            insert.bind(3, passwordSalt);
            insert.bind(4, subscribeKey);
            insert.bind(5, System.currentTimeMillis());
            insert.step();
            insert.dispose();
        } catch (final SQLiteException e) {
            if (e.getErrorCode() == SQLITE_CONSTRAINT_UNIQUE) {
                throw new GeneralSecurityException("username already registered");
            }
            throw e;
        } finally {
            conn.dispose();
        }
    }

    private static class Session {
        final long sessionId;
        final byte[] cookieToken;
        final byte[] requestToken;

        Session(final long sessionId, final byte[] cookieToken, final byte[] requestToken) {
            this.sessionId = sessionId;
            this.cookieToken = cookieToken;
            this.requestToken = requestToken;
        }
    }

    private static Session login(final String username, final String password)
            throws GeneralSecurityException, SQLiteException {
        final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        try {
            open(conn, false);
            final SQLiteStatement select = conn.prepare("SELECT userId, passwordHash, " +
                    "passwordSalt FROM Accounts WHERE username = ?");
            select.bind(1, username);
            if (!select.step()) {
                throw new GeneralSecurityException("invalid username");
            }
            final long userId = select.columnLong(0);
            final byte[] passwordHash = select.columnBlob(1);
            final byte[] passwordSalt = select.columnBlob(2);
            select.dispose();
            if (!MessageDigest.isEqual(hash(password.getBytes(), passwordSalt), passwordHash)) {
                throw new GeneralSecurityException("invalid password");
            }

            final long now = System.currentTimeMillis();
            final SQLiteStatement delete = conn.prepare("DELETE FROM Sessions where expiryTime < ?");
            delete.bind(1, now);
            delete.step();
            delete.dispose();

            final SecureRandom random = new SecureRandom();
            final byte[] cookieToken = new byte[32];
            random.nextBytes(cookieToken);
            final byte[] requestToken = new byte[32];
            random.nextBytes(requestToken);

            final SQLiteStatement insert = conn.prepare("INSERT INTO Sessions " +
                    "(userId, cookieToken, requestToken, expiryTime) VALUES (?, ?, ?, ?)");
            insert.bind(1, userId);
            insert.bind(2, cookieToken);
            insert.bind(3, requestToken);
            insert.bind(4, now + SESSION_LENGTH);
            insert.step();
            insert.dispose();

            return new Session(conn.getLastInsertId(), cookieToken, requestToken);
        } finally {
            conn.dispose();
        }
    }

    private static class CreateAccountHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final String username;
                final String password;
                try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                    final JsonObject object = reader.readObject();
                    username = object.getString("username");
                    password = object.getString("password");
                } catch (final ClassCastException | JsonException | NullPointerException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }

                try {
                    createAccount(username, password);
                } catch (final GeneralSecurityException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(400, -1);
                    return;
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1);
                    return;
                }
                exchange.sendResponseHeaders(200, -1);
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static class LoginHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final String username;
                final String password;
                try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                    final JsonObject object = reader.readObject();
                    username = object.getString("username");
                    password = object.getString("password");
                } catch (final ClassCastException | JsonException | NullPointerException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }

                final Session session;
                try {
                    session = login(username, password);
                } catch (final GeneralSecurityException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(403, -1);
                    return;
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1);
                    return;
                }

                final Base64.Encoder encoder = Base64.getEncoder();
                final byte[] requestToken = encoder.encode(session.requestToken);
                exchange.getResponseHeaders().set("Set-Cookie",
                        String.format("__Host-session=%d|%s; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=%d",
                            session.sessionId, new String(encoder.encode(session.cookieToken)),
                            SESSION_LENGTH / 1000));
                exchange.sendResponseHeaders(200, requestToken.length);
                try (final OutputStream output = exchange.getResponseBody()) {
                    output.write(requestToken);
                }
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static class LogoutHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final Account account = verifySession(exchange, true, null);
                if (account == null) {
                    return;
                }
                clearCookie(exchange);
                exchange.sendResponseHeaders(200, -1);
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static class LogoutEverywhereHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                try {
                    final Account account = verifySession(exchange, false, null);
                    if (account == null) {
                        return;
                    }
                    final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
                    try {
                        open(conn, false);

                        final SQLiteStatement select = conn.prepare("DELETE from Sessions where userId = ?");
                        select.bind(1, account.userId);
                        select.step();
                        select.dispose();
                    } finally {
                        conn.dispose();
                    }
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1);
                    return;
                }
                clearCookie(exchange);
                exchange.sendResponseHeaders(200, -1);
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
    private static class RotateHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final Account account = verifySession(exchange, false, null);
                if (account == null) {
                    return;
                }
                final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
                try {
                    open(conn, false);

                    final SecureRandom random = new SecureRandom();
                    final byte[] subscribeKey = new byte[32];
                    random.nextBytes(subscribeKey);

                    final SQLiteStatement select = conn.prepare("UPDATE Accounts SET subscribeKey = ? where userId = ?");
                    select.bind(1, subscribeKey);
                    select.bind(2, account.userId);
                    select.step();
                    select.dispose();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1);
                    return;
                } finally {
                    conn.dispose();
                }
                exchange.sendResponseHeaders(200, -1);
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static String getCookie(final HttpExchange exchange, final String key) {
        final List<String> cookieHeaders = exchange.getRequestHeaders().get("Cookie");
        if (cookieHeaders == null) {
            return null;
        }
        for (final String cookieHeader : cookieHeaders) {
            final String[] cookies = cookieHeader.split(";");
            for (final String cookie : cookies) {
                final String[] keyValue = cookie.trim().split("=", 2);
                if (keyValue.length == 2) {
                    if (keyValue[0].equals(key)) {
                        return keyValue[1];
                    }
                }
            }
        }
        return null;
    }

    private static class Account {
        final long userId;
        final String username;
        final byte[] subscribeKey;
        final int verifyInterval;

        Account(final long userId, final String username, final byte[] subscribeKey,
                final int verifyInterval) {
            this.userId = userId;
            this.username = username;
            this.subscribeKey = subscribeKey;
            this.verifyInterval = verifyInterval;
        }
    }

    private static void clearCookie(final HttpExchange exchange) {
        exchange.getResponseHeaders().set("Set-Cookie",
                "__Host-session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
    }

    private static Account verifySession(final HttpExchange exchange, final boolean end, byte[] requestTokenEncoded)
            throws IOException {
        final String cookie = getCookie(exchange, "__Host-session");
        if (cookie == null) {
            exchange.sendResponseHeaders(403, -1);
            return null;
        }
        final String[] session = cookie.split("\\|", 2);
        if (session.length != 2) {
            clearCookie(exchange);
            exchange.sendResponseHeaders(403, -1);
            return null;
        }
        final long sessionId = Long.parseLong(session[0]);
        final byte[] cookieToken = Base64.getDecoder().decode(session[1]);

        if (requestTokenEncoded == null) {
            requestTokenEncoded = new byte[session[1].length()];
            final DataInputStream input = new DataInputStream(exchange.getRequestBody());
            try {
                input.readFully(requestTokenEncoded);
            } catch (final EOFException e) {
                clearCookie(exchange);
                exchange.sendResponseHeaders(403, -1);
                return null;
            }
        }
        final byte[] requestToken = Base64.getDecoder().decode(requestTokenEncoded);

        final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        try {
            open(conn, !end);

            final SQLiteStatement select = conn.prepare("SELECT cookieToken, requestToken, " +
                    "expiryTime, username, subscribeKey, Accounts.userId, verifyInterval " +
                    "FROM Sessions " +
                    "INNER JOIN Accounts on Accounts.userId = Sessions.userId " +
                    "WHERE sessionId = ?");
            select.bind(1, sessionId);
            if (!select.step() || !MessageDigest.isEqual(cookieToken, select.columnBlob(0)) ||
                    !MessageDigest.isEqual(requestToken, select.columnBlob(1))) {
                clearCookie(exchange);
                exchange.sendResponseHeaders(403, -1);
                return null;
            }

            if (select.columnLong(2) < System.currentTimeMillis()) {
                clearCookie(exchange);
                exchange.sendResponseHeaders(403, -1);
                return null;
            }

            if (end) {
                final SQLiteStatement delete = conn.prepare("DELETE FROM Sessions " +
                        "WHERE sessionId = ?");
                delete.bind(1, sessionId);
                delete.step();
                delete.dispose();
            }

            return new Account(select.columnLong(5), select.columnString(3), select.columnBlob(4),
                    select.columnInt(6));
        } catch (final SQLiteException e) {
            exchange.sendResponseHeaders(500, -1);
            return null;
        } finally {
            conn.dispose();
        }
    }

    private static class AccountHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final Account account = verifySession(exchange, false, null);
                if (account == null) {
                    return;
                }
                final JsonObjectBuilder accountJson = Json.createObjectBuilder();
                accountJson.add("username", account.username);
                accountJson.add("verifyInterval", account.verifyInterval);
                exchange.sendResponseHeaders(200, 0);
                try (final OutputStream output = exchange.getResponseBody();
                        final JsonWriter writer = Json.createWriter(output)) {
                    writer.write(accountJson.build());
                }
                return;
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static void createQrCode(final byte[] contents, final OutputStream output) throws IOException {
        final BitMatrix result;
        try {
            final QRCodeWriter writer = new QRCodeWriter();
            final Map<EncodeHintType,Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.CHARACTER_SET, "ISO-8859-1");
            try {
                result = writer.encode(new String(contents, "ISO-8859-1"), BarcodeFormat.QR_CODE,
                        QR_CODE_SIZE, QR_CODE_SIZE, hints);
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("ISO-8859-1 not supported", e);
            }
        } catch (WriterException e) {
            throw new RuntimeException(e);
        }

        MatrixToImageWriter.writeToStream(result, "png", output);
    }

    private static class AccountQrHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                exchange.getResponseHeaders().set("Cache-Control", "public, max-age=1800");
                exchange.sendResponseHeaders(200, 0);
                try (final OutputStream output = exchange.getResponseBody()) {
                    final String contents = "attestation.copperhead.co 0 " +
                            BaseEncoding.base16().encode(DEMO_SUBSCRIBE_KEY) +
                            " " + DEFAULT_VERIFY_INTERVAL;
                    createQrCode(contents.getBytes(), output);
                }
            } else if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final Account account = verifySession(exchange, false, null);
                if (account == null) {
                    return;
                }
                exchange.sendResponseHeaders(200, 0);
                try (final OutputStream output = exchange.getResponseBody()) {
                    final String contents = "attestation.copperhead.co " +
                        account.userId + " " +
                        BaseEncoding.base16().encode(account.subscribeKey) + " " +
                        account.verifyInterval;
                    createQrCode(contents.getBytes(), output);
                }
                return;
            } else {
                exchange.getResponseHeaders().set("Allow", "GET, POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static class ConfigurationHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final int verifyInterval;
                final String requestToken;
                try (final JsonReader reader = Json.createReader(exchange.getRequestBody())) {
                    final JsonObject object = reader.readObject();
                    requestToken = object.getString("requestToken");
                    verifyInterval = object.getInt("verifyInterval");
                } catch (final ClassCastException | JsonException | NullPointerException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }

                final Account account = verifySession(exchange, false, requestToken.getBytes(StandardCharsets.UTF_8));
                if (account == null) {
                    return;
                }

                if (verifyInterval < 3600 || verifyInterval > 604800) {
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }

                final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
                try {
                    open(conn, false);
                    final SQLiteStatement update = conn.prepare("UPDATE Accounts SET verifyInterval = ? WHERE userId = ?");
                    update.bind(1, verifyInterval);
                    update.bind(2, account.userId);
                    update.step();
                    update.dispose();
                } catch (final SQLiteException e) {
                    e.printStackTrace();
                    final byte[] response = "Failed to save data.\n".getBytes();
                    exchange.sendResponseHeaders(500, response.length);
                    try (final OutputStream output = exchange.getResponseBody()) {
                        output.write(response);
                    }
                    return;
                } finally {
                    conn.dispose();
                }
                exchange.sendResponseHeaders(200, -1);
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static String convertToPem(final byte[] derEncoded) {
        return "-----BEGIN CERTIFICATE-----\n" +
                new String(Base64.getMimeEncoder(64, "\n".getBytes()).encode(derEncoded)) +
                "\n-----END CERTIFICATE-----";
    }

    private static void writeDevicesJson(final HttpExchange exchange, final long userId)
            throws IOException {
        final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
        final JsonArrayBuilder devices = Json.createArrayBuilder();
        try {
            open(conn, true);

            final SQLiteStatement select = conn.prepare("SELECT fingerprint, " +
                    "pinnedCertificate0, pinnedCertificate1, pinnedCertificate2, " +
                    "hex(pinnedVerifiedBootKey), pinnedOsVersion, pinnedOsPatchLevel, " +
                    "pinnedAppVersion, userProfileSecure, enrolledFingerprints, accessibility, " +
                    "deviceAdmin, adbEnabled, addUsersWhenLocked, denyNewUsb, verifiedTimeFirst, " +
                    "verifiedTimeLast FROM Devices WHERE userId is ? ORDER BY verifiedTimeFirst");
            if (userId != 0) {
                select.bind(1, userId);
            }
            while (select.step()) {
                final JsonObjectBuilder device = Json.createObjectBuilder();
                device.add("fingerprint", BaseEncoding.base16().encode(select.columnBlob(0)));
                device.add("pinnedCertificate0", convertToPem(select.columnBlob(1)));
                device.add("pinnedCertificate1", convertToPem(select.columnBlob(2)));
                device.add("pinnedCertificate2", convertToPem(select.columnBlob(3)));
                final String verifiedBootKey = select.columnString(4);
                device.add("verifiedBootKey", verifiedBootKey);
                DeviceInfo info = fingerprintsCopperheadOS.get(verifiedBootKey);
                if (info != null) {
                    device.add("os", "CopperheadOS");
                } else {
                    device.add("os", "Stock");
                    info = fingerprintsStock.get(verifiedBootKey);
                    if (info == null) {
                        throw new RuntimeException("invalid fingerprint");
                    }
                }
                device.add("name", info.name);
                device.add("pinnedOsVersion", select.columnInt(5));
                device.add("pinnedOsPatchLevel", select.columnInt(6));
                device.add("pinnedAppVersion", select.columnInt(7));
                device.add("userProfileSecure", select.columnInt(8));
                device.add("enrolledFingerprints", select.columnInt(9));
                device.add("accessibility", select.columnInt(10));
                device.add("deviceAdmin", select.columnInt(11));
                device.add("adbEnabled", select.columnInt(12));
                device.add("addUsersWhenLocked", select.columnInt(13));
                device.add("denyNewUsb", select.columnInt(14));
                device.add("verifiedTimeFirst", select.columnLong(15));
                device.add("verifiedTimeLast", select.columnLong(16));

                final SQLiteStatement history = conn.prepare("SELECT time, strong, teeEnforced, " +
                        "osEnforced FROM Attestations WHERE fingerprint = ? ORDER BY time");
                history.bind(1, select.columnBlob(0));

                final JsonArrayBuilder attestations = Json.createArrayBuilder();
                while (history.step()) {
                    attestations.add(Json.createObjectBuilder()
                            .add("time", history.columnLong(0))
                            .add("strong", history.columnInt(1) != 0)
                            .add("teeEnforced", history.columnString(2))
                            .add("osEnforced", history.columnString(3)));
                }
                history.dispose();
                device.add("attestations", attestations);

                devices.add(device);
            }
            select.dispose();
        } catch (final SQLiteException e) {
            e.printStackTrace();
            exchange.sendResponseHeaders(500, -1);
            return;
        } finally {
            conn.dispose();
        }

        exchange.sendResponseHeaders(200, 0);
        try (final OutputStream output = exchange.getResponseBody();
                final JsonWriter writer = Json.createWriter(output)) {
            writer.write(devices.build());
        }
    }

    private static class DevicesHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("GET")) {
                writeDevicesJson(exchange, 0);
            } else if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final Account account = verifySession(exchange, false, null);
                if (account == null) {
                    return;
                }
                writeDevicesJson(exchange, account.userId);
            } else {
                exchange.getResponseHeaders().set("Allow", "GET, POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static class ChallengeHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final byte[] challenge = AttestationProtocol.getChallenge();
                pendingChallenges.put(ByteBuffer.wrap(challenge), true);

                final byte[] challengeMessage =
                        Bytes.concat(new byte[]{AttestationProtocol.PROTOCOL_VERSION},
                                challengeIndex, challenge);

                exchange.sendResponseHeaders(200, challengeMessage.length);
                try (final OutputStream output = exchange.getResponseBody()) {
                    output.write(challengeMessage);
                }
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }

    private static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                final List<String> authorization = exchange.getRequestHeaders().get("Authorization");
                if (authorization == null) {
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }
                final StringReader token = new StringReader(authorization.get(0).split(" ", 2)[1]);

                long userId;
                final String subscribeKey;
                try (final JsonReader reader = Json.createReader(token)) {
                    final JsonObject object = reader.readObject();
                    userId = object.getJsonNumber("userId").longValue();
                    subscribeKey = object.getString("subscribeKey", null);
                } catch (final ClassCastException | JsonException | NullPointerException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }

                final byte[] currentSubscribeKey;
                final int verifyInterval;
                final byte[] subscribeKeyDecoded = BaseEncoding.base16().decode(subscribeKey);
                if (userId != 0) {
                    final SQLiteConnection conn = new SQLiteConnection(AttestationProtocol.ATTESTATION_DATABASE);
                    try {
                        open(conn, true);

                        final SQLiteStatement select = conn.prepare("SELECT subscribeKey, verifyInterval FROM Accounts WHERE userId = ?");
                        select.bind(1, userId);
                        select.step();
                        currentSubscribeKey = select.columnBlob(0);
                        verifyInterval = select.columnInt(1);
                        select.dispose();
                    } catch (final SQLiteException e) {
                        exchange.sendResponseHeaders(403, -1);
                        return;
                    } finally {
                        conn.dispose();
                    }
                } else {
                    currentSubscribeKey = DEMO_SUBSCRIBE_KEY;
                    verifyInterval = DEFAULT_VERIFY_INTERVAL;
                }

                if (subscribeKey == null) {
                    userId = -1;
                } else if (!MessageDigest.isEqual(subscribeKeyDecoded, currentSubscribeKey)) {
                    exchange.sendResponseHeaders(400, -1);
                    return;
                }

                final InputStream input = exchange.getRequestBody();

                final ByteArrayOutputStream attestation = new ByteArrayOutputStream();
                final byte[] buffer = new byte[4096];
                for (int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                    attestation.write(buffer, 0, read);

                    if (attestation.size() > AttestationProtocol.MAX_MESSAGE_SIZE) {
                        final byte[] response = "Attestation too large".getBytes();
                        exchange.sendResponseHeaders(400, response.length);
                        try (final OutputStream output = exchange.getResponseBody()) {
                            output.write(response);
                        }
                        return;
                    }
                }

                final byte[] attestationResult = attestation.toByteArray();

                try {
                    AttestationProtocol.verifySerialized(attestationResult, pendingChallenges, userId);
                } catch (final BufferUnderflowException | DataFormatException | GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    final byte[] response = "Error\n".getBytes();
                    exchange.sendResponseHeaders(400, response.length);
                    try (final OutputStream output = exchange.getResponseBody()) {
                        output.write(response);
                    }
                    return;
                }

                final JsonObjectBuilder result = Json.createObjectBuilder();
                result.add("subscribeKey", BaseEncoding.base16().encode(currentSubscribeKey));
                result.add("verifyInterval", verifyInterval);

                exchange.sendResponseHeaders(200, 0);
                try (final OutputStream output = exchange.getResponseBody();
                        final JsonWriter writer = Json.createWriter(output)) {
                    writer.write(result.build());
                }
            } else {
                exchange.getResponseHeaders().set("Allow", "POST");
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
}
