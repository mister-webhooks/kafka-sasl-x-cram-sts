package com.mister_webhooks.sasl.x_cram_sts.internal;

import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.arns.ArnResource;

import java.util.Optional;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public sealed interface ARNMatcher {

  static ARNMatcher fromString(String arnMatchString) throws ARNResourceMatcher.ResourceMatchSyntaxError {
    return fromARN(Arn.fromString(arnMatchString));
  }

  static ARNMatcher fromARN(Arn arnPattern) throws ARNResourceMatcher.ResourceMatchSyntaxError {
    ARNMatcher arnPatternMatcher = new ARNPattern(arnPattern);

    if (arnPattern.service().equals("iam")
      && arnPattern.resource().resourceType().isPresent()
      && arnPattern.resource().resourceType().get().equals("role")) {

      ArnResource.Builder resourceBuilder = ArnResource.builder();
      resourceBuilder.resourceType("assumed-role");
      resourceBuilder.resource(arnPattern.resource().resource());
      resourceBuilder.qualifier("*");

      Arn.Builder arnBuilder = Arn.builder()
        .partition(arnPattern.partition())
        .service("sts")
        .resource(resourceBuilder.build().toString().replace(':', '/'));

      if (arnPattern.region().isPresent())
        arnBuilder = arnBuilder.region(arnPattern.region().get());

      if (arnPattern.accountId().isPresent())
        arnBuilder = arnBuilder.accountId(arnPattern.accountId().get());

      ARNMatcher assumedRoleMatcher = new ARNPattern(arnBuilder.build());

      return new Pair(arnPatternMatcher, assumedRoleMatcher);
    }

    return arnPatternMatcher;
  }

  boolean match(Arn candidate);

  default boolean match(String candidateARN) {
    return match(Arn.fromString(candidateARN));
  }

  final class ARNPattern implements ARNMatcher {
    private final String partition;
    private final String service;
    private final Optional<AWSGlob> region;
    private final Optional<AWSGlob> accountId;
    private final ARNResourceMatcher resource;
    private final Character resourceDelimiter;

    private ARNPattern(Arn matcherArn) throws ARNResourceMatcher.ResourceMatchSyntaxError {
      this.partition = matcherArn.partition();
      this.service = matcherArn.service();
      this.region = matcherArn.region().map(AWSGlob::new);
      this.accountId = matcherArn.accountId().map(AWSGlob::new);
      this.resource = ARNResourceMatcher.forResource(matcherArn.resource());
      this.resourceDelimiter = matcherArn.resourceAsString().contains("/") ? '/' : ':';
    }

    private static boolean matchOptional(Optional<AWSGlob> pattern, Optional<String> candidate) {
      return pattern
        .map(arnMatcher -> candidate.filter(arnMatcher::match).isPresent())
        .orElse(true);
    }

    public boolean match(Arn candidate) {
      return this.partition.equals(candidate.partition()) &&
        this.service.equals(candidate.service()) &&
        matchOptional(this.region, candidate.region()) &&
        matchOptional(this.accountId, candidate.accountId()) &&
        this.resource.match(candidate.resource());
    }

    @Override
    public String toString() {
      return "aws:" + this.partition
        + ":" + this.service
        + ":" + this.region.orElse(new AWSGlob("*"))
        + ":" + this.accountId.orElse(new AWSGlob("*"))
        + ":" + this.resource.toString().replace(':', this.resourceDelimiter);
    }
  }

  final class Pair implements ARNMatcher {
    private final ARNMatcher left;
    private final ARNMatcher right;

    private Pair(ARNMatcher left, ARNMatcher right) {
      this.left = left;
      this.right = right;
    }

    public boolean match(Arn candidate) {
      return this.left.match(candidate) || this.right.match(candidate);
    }

    @Override
    public String toString() {
      return this.left.toString() + " || " + this.right.toString();
    }
  }
}

