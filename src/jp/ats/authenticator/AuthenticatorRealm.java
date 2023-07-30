package jp.ats.authenticator;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.Principal;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import jp.ats.authenticator.Authenticator.Result;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;

public class AuthenticatorRealm extends RealmBase {

	private Authenticator authenticator;

	private DataSource dataSource;

	private static final Map<String, LockInfo> lockoutUsers = new HashMap<String, LockInfo>();

	@Override
	protected String getName() {
		return getClass().getName();
	}

	@Override
	public Principal authenticate(String username, String password) {
		Authenticator authenticator = getAuthenticator();
		if (authenticator == null) throw new IllegalStateException();

		Authenticator.setMessageOnCurrentThread(null);

		synchronized (lockoutUsers) {
			LockInfo lock = lockoutUsers.get(username);

			//一度でもログインを試していた場合
			if (lock != null) {
				//リトライ回数が制限値以上の場合
				if (lock.retry >= authenticator.getPermittedRetryCount()) {
					if (lock.lockoutLimit == null) {
						lock.lockoutLimit = new Date(System.currentTimeMillis()
							+ authenticator.getLockoutSeconds()
							* 1000);
					}

					//ロックアウト時間にまだ達していない場合、認証失敗
					if (lock.lockoutLimit.getTime() > System.currentTimeMillis()) {
						//ログイン失敗画面にロックアウトされている旨のメッセージを出せるように
						//このスレッドにロックアウト時間を紐付けておく
						Authenticator.setLockoutLimitOnCurrentThread(lock.lockoutLimit);
						Authenticator.setMessageOnCurrentThread("認証に複数回失敗したので現在アカウントはロックされています");
						return null;
					}

					//リセット
					lock.retry = 1;
					lock.lockoutLimit = null;
				} else {
					lock.retry++;
				}
			} else { //初回ログイン時
				lock = new LockInfo();
				lock.retry = 1;
				lockoutUsers.put(username, lock);
			}
		}

		synchronized (this) {
			if (dataSource == null) {
				try {
					dataSource = (DataSource) new InitialContext().lookup("java:comp/env/jdbc/datasource");
				} catch (NamingException e) {
					throw new IllegalStateException(e);
				}
			}
		}

		Result result;
		try {
			Connection connection = dataSource.getConnection();
			try {
				result = authenticator.fetch(connection, username);
			} finally {
				connection.close();
			}
		} catch (SQLException e) {
			throw new IllegalStateException(e);
		}

		if (result == null) {
			Authenticator.setMessageOnCurrentThread("ログインできません");
			return null;
		}

		if (!authenticator.authenticate(result, username, password)) return null;

		synchronized (lockoutUsers) {
			lockoutUsers.remove(username);
		}

		return new GenericPrincipal(
			username,
			result.password,
			Arrays.asList(result.roles));
	}

	@Override
	protected String getPassword(String username) {
		return null;
	}

	@Override
	protected Principal getPrincipal(String username) {
		return null;
	}

	private synchronized Authenticator getAuthenticator() {
		if (authenticator == null) {
			try {
				String path = findPath();
				Enumeration<URL> enumeration = getClass().getClassLoader()
					.getResources("jp.ats.authenticator");
				while (enumeration.hasMoreElements()) {
					authenticator = readAuthenticator(
						enumeration.nextElement(),
						path);

					//一番最初に見つかったものを使用する
					if (authenticator != null) break;
				}
			} catch (Exception e) {
				throw new IllegalStateException(e);
			}
		}

		return authenticator;
	}

	private String findPath() {
		Container container = getContainer();
		while (container != null && !(container instanceof Context)) {
			container = container.getParent();
		}

		String path = ((Context) container).getPath();

		if (path.startsWith("/")) return path;
		return "/" + path;
	}

	private static Authenticator readAuthenticator(URL url, String path)
		throws Exception {
		BufferedReader reader = new BufferedReader(new InputStreamReader(
			url.openStream()));
		String line;
		while ((line = reader.readLine()) != null) {
			Authenticator authenticator = (Authenticator) Class.forName(
				line.trim()).newInstance();

			//一番最初に見つかったものを返す
			if (authenticator.getApplicationPath().equals(path)) return authenticator;
		}

		return null;
	}

	private static class LockInfo {

		private Date lockoutLimit;

		private int retry;
	}
}
