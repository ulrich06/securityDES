package com.polytech;

public class AsymetricTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Entity test = new Entity();
		String message = "Coucou";
		byte[] signMessage = test.mySign(message.getBytes());
		System.out.println(test.myCheckSignature(message.getBytes(), signMessage, test.thePublicKey));
		

	}

}
