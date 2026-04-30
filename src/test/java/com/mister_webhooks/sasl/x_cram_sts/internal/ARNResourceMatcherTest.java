package com.mister_webhooks.sasl.x_cram_sts.internal;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertThrows;
import static org.testng.AssertJUnit.assertEquals;

public class ARNResourceMatcherTest {
  @DataProvider(name = "matchCases")
  private Object[][] cases() {
    return new Object[][]{
      {"assumed-role/some_role/jesse", "assumed-role/some_role/jesse", true},
      {"assumed-role/some_role/*", "assumed-role/some_role/jesse", true},
      {"assumed-role/*/*", "assumed-role/some_role/jesse", true},
    };
  }

  @DataProvider(name = "syntaxErrors")
  private Object[][] syntaxErrors() {
    return new Object[][]{
      {"*/*/*", "assumed-role/some_role/jesse"},
      {"????/foobar", "role/foobar"},
      {"*/*", "assumed-role/some_role/jesse"}
    };
  }

  @Test(dataProvider = "matchCases")
  public void testMatch(String pattern, String candidate, boolean expected) throws ARNResourceMatcher.ResourceMatchSyntaxError {
    assertEquals(String.format("AWSResourceMatcher[%s] =~ %s", pattern, candidate),
      expected,
      ARNResourceMatcher.forResource(pattern).match(candidate));
  }

  @Test(dataProvider = "syntaxErrors")
  public void testSyntaxError(String pattern, String candidate) {
    assertThrows(
      ARNResourceMatcher.ResourceMatchSyntaxError.class,
      () -> ARNResourceMatcher.forResource(pattern).match(candidate)
    );
  }
}