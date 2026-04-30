package com.mister_webhooks.sasl.x_cram_sts;

import javax.security.auth.callback.Callback;

/* Authentication callback for SASL/AWS-GET-CLIENT-IDENTITY authentication. Callback
 * handler must set authorized flag to true if the ARN is authorized to become the
 * named user.
 */
public class ARNCallback implements Callback {
  private final String arn;
  private boolean authorized = false;

  public ARNCallback(String arn) {
    this.arn = arn;
  }

  public String arn() {
    return this.arn;
  }

  public boolean authorized() {
    return this.authorized;
  }

  public void authorized(boolean authorized) {
    this.authorized = authorized;
  }
}
