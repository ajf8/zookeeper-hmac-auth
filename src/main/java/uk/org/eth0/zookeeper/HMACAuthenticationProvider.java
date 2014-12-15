package uk.org.eth0.zookeeper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.zookeeper.KeeperException.Code;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.NIOServerCnxn;
import org.apache.zookeeper.server.ServerCnxn;
import org.apache.zookeeper.server.auth.AuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.codec.binary.Hex;

public class HMACAuthenticationProvider implements AuthenticationProvider {
	private static final Logger LOG = LoggerFactory
			.getLogger(HMACAuthenticationProvider.class);
	private static final Charset CHARSET = Charset.forName("UTF-8");

	private String sanitizeUsername(String name) {
		return name.replaceAll("[^A-Za-z0-9]", "");
	}

	private class HMACUser {
		private List<String> roles;
		private String name;
		private byte[] privateKey;

		public HMACUser(String name) {
			this.name = name;
		}
		
		public void setPrivateKey(String privateKey) {
			this.roles = new ArrayList<String>();
			this.privateKey = privateKey.getBytes(CHARSET);
		}

		private SecretKeySpec getSecretKeySpec(String secret) {
			return new SecretKeySpec(secret.getBytes(CHARSET), "RAW");
		}

		public void addRole(String role) {
			this.roles.add(role);
		}
		
		public List<String> getRoles() {
			return this.roles;
		}
		
		public boolean isValidConfig() {
			return this.privateKey != null;
		}

		public String getHash(String sessionId) throws InvalidKeyException,
				NoSuchAlgorithmException {
			Mac mac = getMac();
			mac.init(getSecretKeySpec(sessionId));
			byte[] rawHmac = mac.doFinal(this.privateKey);
			return Hex.encodeHexString(rawHmac);
		}

		public boolean validate(String sessionId, String hash)
				throws InvalidKeyException, NoSuchAlgorithmException {
			return getHash(sessionId).equals(hash);
		}
	}

	@Override
	public String getScheme() {
		return "hmac";
	}

	private static Mac getMac() throws NoSuchAlgorithmException {
		return Mac.getInstance("HmacSHA1");
	}

	private String getConfigBase() {
		String base = System.getProperty("zookeeper.hmacauth.configdir");
		if (base == null) {
			base = "/etc/zookeeper/auth";
		}
		return base;
	}

	private String getConfigPathForUser(String user) {
		return getConfigBase() + "/" + user;
	}

	private HMACUser getUser(String name) {
		String path = getConfigPathForUser(name);
		LOG.info("looking in "+path);
		File file = new File(path);

		if (!file.exists()) {
			LOG.debug("File " + path + " does not exist.");
			return null;
		}
		
		HMACUser user = new HMACUser(name);
		
		try {
			BufferedReader br = new BufferedReader(new FileReader(file));
			String line = null;
			while ((line = br.readLine()) != null) {
				String[] keyValue = line.split("=");
				if (keyValue.length != 2) continue;
				String key = keyValue[0];
				if (key.length() < 1) continue;
				String value = keyValue[1];
				if (value.length() < 1) continue;
				if (key.equals("key")) {
					user.setPrivateKey(value);
				} else if (key.equals("roles")) {
					for (String role : value.split(",")) {
						user.addRole(role);
					}
				}
			}
			
			br.close();
		} catch (IOException e) {
			return null;
		}
		
		if (!user.isValidConfig()) {
			LOG.error("Config for user "+name+" is not valid.");
			return null;
		}
		
		return user;
	}

	@Override
	public Code handleAuthentication(ServerCnxn cnxn, byte[] rawAuthData) {
		String sessionId = "0";

		if (cnxn instanceof NIOServerCnxn) {
			NIOServerCnxn ncnxn = (NIOServerCnxn) cnxn;
		    sessionId = String.valueOf(ncnxn.getSessionId());
		} else {
			LOG.error("ServerCnxn implementation not compatible.");
			return Code.AUTHFAILED;
		}

		String authData = new String(rawAuthData, Charset.forName("UTF-8"));
		String[] authDataFields = authData.split(":");

		if (authDataFields.length != 2) {
			return Code.AUTHFAILED;
		}

		String userName = sanitizeUsername(authDataFields[0]);
		String hash = authDataFields[1];
		
		HMACUser user = getUser(userName);
		if (user == null) {
			return Code.AUTHFAILED;
		}
		
		try {
			if (!user.validate(sessionId, hash)) {
				LOG.error("User "+userName+" failed HMAC validation.");
				return Code.AUTHFAILED;
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			return Code.AUTHFAILED;
		}

		for (String role : user.getRoles()) {
			cnxn.addAuthInfo(new Id(getScheme(), role));
		}
		
		return Code.OK;
	}

	@Override
	public boolean matches(String id, String aclExpr) {
		if (id == null || id.isEmpty() || aclExpr == null || aclExpr.isEmpty()) {
			return false;
		}
		return id == aclExpr;
	}

	@Override
	public boolean isAuthenticated() {
		return true;
	}

	@Override
	public boolean isValid(String id) {
		// A valid user name is at least 1 char length
		return id != null && !id.isEmpty() && id.length() == 1;
	}

}
