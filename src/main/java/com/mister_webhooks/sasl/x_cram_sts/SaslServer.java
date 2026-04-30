package com.mister_webhooks.sasl.x_cram_sts;

import com.mister_webhooks.sasl.x_cram_sts.internal.StateMachine;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServerFactory;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

public class SaslServer implements javax.security.sasl.SaslServer {
  private static final Logger logger = LoggerFactory.getLogger(SaslServer.class);
  public static final String MECHANISM = "X-CRAM-STS";
  private final StateMachine stateMachine;

  private boolean complete = false;
  private String authorizationId;

  private SaslServer(CallbackHandler callbackHandler, String challenge) {
    this.authorizationId = "";
    this.stateMachine = new StateMachine(
      challenge,
      callbackHandler,
      (authid) -> {
        this.authorizationId = authid;
        this.complete = true;
      });
  }

  @Override
  public String getMechanismName() {
    return MECHANISM;
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    List<String> tokens = extractTokens(new String(response, StandardCharsets.UTF_8));
    return this.stateMachine.accept(tokens);
  }

  @Override
  public boolean isComplete() {
    return this.complete;
  }

  @Override
  public String getAuthorizationID() {
    return this.authorizationId;
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) {
    return new byte[0];
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) {
    return new byte[0];
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    return null;
  }

  @Override
  public void dispose() {}

  @NotNull
  private List<String> extractTokens(@NotNull String string) {
    List<String> tokens = new ArrayList<>();
    int startIndex = 0;
    while (true) {
      int endIndex = string.indexOf("\u0000", startIndex);
      if (endIndex == -1) {
        tokens.add(string.substring(startIndex));
        break;
      }
      tokens.add(string.substring(startIndex, endIndex));
      startIndex = endIndex + 1;
    }

    return tokens;
  }

  private static class ChallengeGenerator {
    private final static int minPrintable = 0x21;
    private final static int maxPrintable = 0x7c;

    private final Random random = new SecureRandom();

    public String generate(int length) {
      return random
        .ints(length, minPrintable, maxPrintable)
        .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
        .toString();
    }
  }
  public static class Factory implements SaslServerFactory {
    private static final int DEFAULT_CHALLENGE_SIZE = 32;
    private static final ChallengeGenerator challengeGenerator = new ChallengeGenerator();

    @Override
    public javax.security.sasl.SaslServer createSaslServer(String mechanism,
                                                           String protocol,
                                                           String serverName,
                                                           Map<String, ?> props,
                                                           CallbackHandler cbh) throws SaslException {

      if (!MECHANISM.equals(mechanism))
        throw new SaslException(String.format("Mechanism '%s' is not supported. Only %s is supported.",
          mechanism,
          MECHANISM));

      final Integer challengeSize =
        Optional.ofNullable((String) props.get("com.mister_webhooks.sasl.x_cram_sts.server.challenge_size"))
          .map(Integer::parseInt)
          .orElse(DEFAULT_CHALLENGE_SIZE);

      logger.debug("{}://{} {} authentication using challengeSize={}", protocol, serverName, mechanism, challengeSize);

      return new SaslServer(cbh, challengeGenerator.generate(challengeSize));
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
      return new String[]{MECHANISM};
    }
  }
}