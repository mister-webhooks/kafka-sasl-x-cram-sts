package com.mister_webhooks.sasl.x_cram_sts.internal;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.AssertJUnit.assertEquals;

public class AWSGlobTest {

  @DataProvider(name = "matchCases")
  private Object[][] cases() {
    return new Object[][]{
      {"*", "foobar", true},
      {"*", "", true},
      {"?", "", false},
      {"h?llo", "hello", true},
      {"h?llo", "hullo", true},
      {"h?llo", "hllo", false},
      {"hello", "hello", true},
      {"hello", "hullo", false},
      {"hello", "", false},
      {"", "hello", false},
      {"", "", true},
    };
  }

  @Test(dataProvider = "matchCases")
  public void testMatch(String glob, String candidate, boolean expected) {
    assertEquals(String.format("AWSGlob[%s] =~ %s", glob, candidate),
      expected,
      new AWSGlob(glob).match(candidate));
  }
}