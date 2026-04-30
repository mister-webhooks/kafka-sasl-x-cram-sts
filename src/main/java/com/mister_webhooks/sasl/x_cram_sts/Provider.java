package com.mister_webhooks.sasl.x_cram_sts;

import java.security.Security;

public class Provider extends java.security.Provider {
  private static final long serialVersionUID = 1L;

  private Provider() {
    super("Simple SASL/X-CRAM-STS Server Provider",
      "1.0",
      "Simple SASL/X-CRAM-STS Server Provider for Kafka");

    put("SaslServerFactory." + SaslServer.MECHANISM,
      SaslServer.Factory.class.getName());
  }

  public static void initialize() {
    Security.addProvider(new Provider());
  }
}
