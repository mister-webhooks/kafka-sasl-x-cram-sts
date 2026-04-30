package com.mister_webhooks.sasl.x_cram_sts.internal;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertThrows;
import static org.testng.AssertJUnit.assertEquals;

public class ARNMatcherTest {
  @DataProvider(name = "matchCases")
  private Object[][] cases() {
    return new Object[][]{
      {"arn:aws:sts::350784047695:assumed-role/some_role/jesse",
        "arn:aws:sts::350784047695:assumed-role/some_role/jesse",
        true
      },
      {"arn:aws:sts::123456789012:assumed-role/some_role/jesse",
        "arn:aws:sts::123456789011:assumed-role/some_role/jesse",
        false
      },
      {"arn:aws:sts::*:assumed-role/some_role/*",
        "arn:aws:sts::350784047695:assumed-role/some_role/jesse",
        true
      },
      {"arn:aws:sts::*:assumed-role/*",
        "arn:aws:sts::350784047695:assumed-role/some_role/jesse",
        false
      },
      {"arn:aws:iam::*:role/*",
        "arn:aws:sts::350784047695:assumed-role/some_role/jesse",
        true
      },
      {"arn:aws:iam::*:role/some_role",
        "arn:aws:sts::350784047695:assumed-role/some_role/jesse",
        true
      },
      {"arn:aws:iam::*:role/le_role",
        "arn:aws:sts::350784047695:assumed-role/some_role/jesse",
        false
      },
    };
  }

  @DataProvider(name = "syntaxErrors")
  private Object[] syntaxErrors() {
    return new Object[][]{
      {"arn:aws:sts::123456789012:*/some_role"}
    };
  }

  @Test(dataProvider = "matchCases")
  public void testMatch(String pattern, String candidate, boolean expected) throws ARNResourceMatcher.ResourceMatchSyntaxError {
    assertEquals(String.format("ARNMatcher[%s] =~ %s", pattern, candidate),
      expected,
      ARNMatcher.fromString(pattern).match(candidate));
  }

  @Test(dataProvider = "syntaxErrors")
  public void testBadPattern(String badPattern) {
    assertThrows(
      ARNResourceMatcher.ResourceMatchSyntaxError.class,
      () -> ARNMatcher.fromString(badPattern)
    );
  }
}