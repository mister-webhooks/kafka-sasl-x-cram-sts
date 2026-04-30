package com.mister_webhooks.sasl.x_cram_sts.internal;

import com.mister_webhooks.sasl.x_cram_sts.ARNCallback;
import com.mister_webhooks.sasl.x_cram_sts.SaslServer;
import org.apache.kafka.common.errors.SaslAuthenticationException;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.SaslException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.SequencedCollection;
import java.util.function.Consumer;

public class StateMachine {
  private static final Logger logger = LoggerFactory.getLogger(StateMachine.class);
  private final String challenge;
  private final CallbackHandler callbackHandler;
  private final Consumer<String> onSuccess;
  private SASLCallback<List<String>, byte[], SaslException> accept;

  public StateMachine(String challenge, CallbackHandler callbackHandler, Consumer<String> onSuccess) {
    this.challenge = challenge;
    this.callbackHandler = callbackHandler;
    this.onSuccess = onSuccess;
    this.accept = this::henlo_and_challenge;
  }

  public byte[] accept(List<String> tokens) throws SaslException {
    return this.accept.apply(tokens);
  }

  @NotNull
  private byte[] henlo_and_challenge(@NotNull SequencedCollection<String> tokens) {
    if (!(tokens.size() == 1 && tokens.getFirst().equals("HENLO FREN"))) {
      throw new SaslAuthenticationException(
        String.format("SASL/%s protocol error: client must commence by sending `HENLO FREN` message", SaslServer.MECHANISM)
      );
    }

    logger.debug("sending challenge `{}` to client", this.challenge);
    this.accept = this::receive_gci_token;
    return this.challenge.getBytes();
  }

  @NotNull
  @Contract("_ -> new")
  private byte[] receive_gci_token(@NotNull List<String> tokens) throws SaslException {
    if (tokens.size() != 2) {
      throw new SaslAuthenticationException("Invalid SASL/X-CRAM-STS response: expected username followed"
        + " by presigned GetCallerIdentity URL"
      );
    }

    String username = tokens.getFirst();
    String principalARN;

    try {
      URIEvaluator exec = URIEvaluator.fromURI(tokens.getLast());
      principalARN = exec.execute(this.challenge);
    } catch (URIEvaluator.SecurityException | URISyntaxException e) {
      throw new SaslAuthenticationException(e.getMessage());
    }

    Callback nameCallback = new NameCallback("username", username);
    ARNCallback arnCallback = new ARNCallback(principalARN);

    try {
      callbackHandler.handle(new Callback[]{nameCallback, arnCallback});
    } catch (Throwable e) {
      throw new SaslAuthenticationException("Authentication failed: credentials for user could not be verified", e);
    }

    if (!arnCallback.authorized())
      throw new SaslAuthenticationException(String.format("Authentication failed: %s cannot log in as %s",
        principalARN,
        username));

    this.onSuccess.accept(username);
    this.accept = this::finished;
    return new byte[0];
  }

  private byte[] finished(List<String> ignoreTokens) throws SaslAuthenticationException {
    throw new SaslAuthenticationException("Protocol error: exchange already completed");
  }

  @FunctionalInterface
  interface SASLCallback<T, R, E extends Exception> {
    R apply(T t) throws E;
  }
}
