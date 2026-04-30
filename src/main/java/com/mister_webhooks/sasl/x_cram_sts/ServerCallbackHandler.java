package com.mister_webhooks.sasl.x_cram_sts;

import com.mister_webhooks.sasl.x_cram_sts.internal.ARNMatcher;
import com.mister_webhooks.sasl.x_cram_sts.internal.ARNResourceMatcher;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class ServerCallbackHandler implements AuthenticateCallbackHandler {
  private static final String CONFIG_BASE = "com.mister_webhooks.security";
  private static final Logger logger = LoggerFactory.getLogger(ServerCallbackHandler.class);

  private final Map<String, List<ARNMatcher>> staticUsers = new HashMap<>();

  @Override
  public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> list) {
    logger.info("configuring X-CRAM-STS callback handler");

    @NotNull List<String> userEntries = configs
      .keySet()
      .stream()
      .filter(k -> k.startsWith(CONFIG_BASE + ".user.iam."))
      .toList();

    logger.info("found user entries: {}", userEntries);

    for (String userKey : userEntries) {
      String username = userKey.substring(userKey.lastIndexOf('.') + 1);
      String arnString = (String) configs.get(userKey);

      if (arnString == null) {
        throw new ConfigException("expected to find one or more ARNs in %s", userKey);
      }

      List<ARNMatcher> arnMatchers = new LinkedList<>();

      for (String arnPattern : arnString.split(",")) {
        try {
          arnMatchers.add(ARNMatcher.fromString(arnPattern));
        } catch (ARNResourceMatcher.ResourceMatchSyntaxError e) {
          logger.error("error parsing ARN pattern `{}`", arnPattern, e);
          throw new RuntimeException(e);
        }
      }
      this.staticUsers.put(username, arnMatchers);
    }

    logger.info("X-CRAM-STS callback handler configured: {}", this.staticUsers);
  }

  @Override
  public void close() {
  }

  @Override
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
    String username = null;

    for (Callback callback : callbacks) {
      switch (callback) {
        case NameCallback nameCallback -> username = nameCallback.getDefaultName();
        case ARNCallback arnCallback -> {

          for (ARNMatcher arnMatcher : this.staticUsers.get(username)) {
            if (arnMatcher.match(arnCallback.arn())) {
              arnCallback.authorized(true);
              break;
            }
          }
        }
        case null, default -> throw new UnsupportedCallbackException(callback);
      }
    }
  }
}
