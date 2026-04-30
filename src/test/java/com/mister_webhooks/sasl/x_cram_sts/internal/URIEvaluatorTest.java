package com.mister_webhooks.sasl.x_cram_sts.internal;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.net.URISyntaxException;
import java.util.Iterator;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;

public class URIEvaluatorTest {

  @DataProvider(name = "bogusURLs")
  private Iterator<String> bogusURLs() {
    return List.of(
      "http://malicious.example",
      "http://not-sts.us-west-2.amazonaws.com",
      "https://not-sts.us-west-2.amazonaws.com",
      "https://sts.us-west-2.evil.amazonaws.com",
      "https://sts.evil.us-west-2.amazonaws.com",
      "https://sts.us-west-2.amazonaws.com?Action=AssumeRole",
      "https://sts.us-west-2.amazonaws.com?Action=AssumeRole&Action=GetCallerIdentity",
      "https://sts.us-west-2.amazonaws.com?Action=GetCallerIdentity&Action=AssumeRole"
    ).iterator();
  }

  @DataProvider(name = "validURLs")
  private Iterator<String> validURLs() {
    return List.of(
      "https://sts.us-west-2.amazonaws.com?Action=GetCallerIdentity&X-Amz-SignedHeaders=challenge%3Bhost"
    ).iterator();
  }

  @Test(dataProvider = "bogusURLs")
  public void testBogus(String bogus) {
    assertThrows(
      URIEvaluator.SecurityException.class,
      () -> URIEvaluator.fromURI(bogus)
    );

  }

  @Test(dataProvider = "validURLs")
  public void testValidURLs(String url) throws URIEvaluator.SecurityException, URISyntaxException {
    assertEquals(
      URIEvaluator.fromURI(url).getURI().toString(),
      url
    );
  }
}