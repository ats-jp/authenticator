package jp.ats.authenticator;

import java.security.MessageDigest;
import java.security.SecureRandom;

public class Digester {

	private static final String DEFAULT_ALGORITHM = "SHA-512";

	private static final SecureRandom random = new SecureRandom();

	public static String digest(String algorithm, String salt, String message) {
		message = (salt == null ? "" : salt) + message;

		MessageDigest digester;
		try {
			digester = MessageDigest.getInstance(algorithm);
		} catch (Exception e) {
			throw new IllegalStateException(e.toString());
		}
		byte[] digested = digester.digest(message.getBytes());

		return convert(digested);
	}

	public static String digest(String salt, String message) {
		return digest(DEFAULT_ALGORITHM, salt, message);
	}

	public static String digest(String message) {
		return digest(DEFAULT_ALGORITHM, "", message);
	}

	public static String createRandomSalt(int size) {
		byte[] bytes = new byte[size / 2];
		random.nextBytes(bytes);
		return convert(bytes);
	}

	private static String convert(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		for (byte b : bytes) {
			builder.append(Integer.toString((b & 0xf0) >> 4, 16));
			builder.append(Integer.toString(b & 0x0f, 16));
		}
		return builder.toString();
	}
}
