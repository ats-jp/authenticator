package jp.ats.authenticator;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Date;

public abstract class Authenticator {

	private static final ThreadLocal<Date> currentLockout = new ThreadLocal<Date>();

	private static final ThreadLocal<String> currentMessage = new ThreadLocal<String>();

	//���Y�X���b�h�̃��O�C�������b�N�A�E�g���ꂽ���ǂ������擾����
	//�`�F�b�N�Ɠ����ɃN���A�����̂ŁA�ꃍ�O�C���ɂ���x�����`�F�b�N�ł��Ȃ�
	//���s���ɂ��̃N���X��u���Ă͂����Ȃ�
	public static Date getLockoutLimitOnCurrentThread() {
		Date limit = currentLockout.get();
		currentLockout.set(null);
		return limit;
	}

	//�`�F�b�N�Ɠ����ɃN���A�����̂ŁA�ꃍ�O�C���ɂ���x�����`�F�b�N�ł��Ȃ�
	//���s���ɂ��̃N���X��u���Ă͂����Ȃ�
	public static String getMessageOnCurrentThread() {
		String message = currentMessage.get();
		currentMessage.set(null);
		return message;
	}

	public static void setMessageOnCurrentThread(String message) {
		currentMessage.set(message);
	}

	static void setLockoutLimitOnCurrentThread(Date limit) {
		currentLockout.set(limit);
	}

	protected boolean authenticate(Result result, String password) {
		if (result.expirationDate != null
			&& result.expirationDate.getTime() < System.currentTimeMillis()) {
			setMessageOnCurrentThread("�p�X���[�h�̗L�����Ԃ��߂��Ă��܂�");
			return false;
		}

		if (!Digester.digest(result.salt, password).equals(result.password)) {
			setMessageOnCurrentThread("���O�C���ł��܂���");
			return false;
		}

		return true;
	}

	protected abstract Result fetch(Connection connection, String username)
		throws SQLException;

	protected abstract String getApplicationPath();

	protected int getLockoutSeconds() {
		return 10;
	}

	protected int getPermittedRetryCount() {
		return 3;
	}

	public static class Result {

		public String password;

		public String salt;

		public Date expirationDate;

		public String[] roles;
	}
}
