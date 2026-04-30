package com.mister_webhooks.sasl.x_cram_sts.internal;

public class AWSGlob {
  private final String glob;

  AWSGlob(String glob) {
    this.glob = glob;
  }

  public boolean match(CharSequence candidate) {
    if (this.glob.equals("*")) {
      return true;
    }

    if (this.glob.length() == candidate.length()) {
      for (int i = 0; i < this.glob.length(); i++) {
        if (!(this.glob.charAt(i) == '?' || this.glob.charAt(i) == candidate.charAt(i))) {
          return false;
        }
      }

      return true;
    }

    return false;
  }

  @Override
  public String toString() {
    return this.glob;
  }
}
