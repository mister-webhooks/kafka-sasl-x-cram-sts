package com.mister_webhooks.sasl.x_cram_sts.internal;

import software.amazon.awssdk.arns.ArnResource;

public sealed interface ARNResourceMatcher {

  static ARNResourceMatcher forResource(String resource) throws ResourceMatchSyntaxError {
    return forResource(ArnResource.fromString(resource));
  }

  static ARNResourceMatcher forResource(ArnResource resource) throws ResourceMatchSyntaxError {
    if (resource.resourceType().isEmpty())
      return new ResourceIDGlob(new AWSGlob(resource.resource()));

    String resourceType = resource.resourceType().get();

    if (resourceType.isEmpty())
      throw new ResourceMatchSyntaxError("resourceType cannot be empty");

    if (resourceType.contains("*") || resourceType.contains("?"))
      throw new ResourceMatchSyntaxError("resourceType cannot contain wildcards");

    if (resource.qualifier().isEmpty())
      return new ResourceTypeAndIDGlob(resourceType, new AWSGlob(resource.resource()));

    return new ResourceTypeAndIDGlobAndQualifierGlob(
      resourceType,
      new AWSGlob(resource.resource()),
      new AWSGlob(resource.qualifier().get())
    );
  }

  boolean match(ArnResource candidate);

  default boolean match(String candidate) {
    return this.match(ArnResource.fromString(candidate));
  }

  final class ResourceIDGlob implements ARNResourceMatcher {
    private final AWSGlob resourceIdPattern;

    private ResourceIDGlob(AWSGlob resourceIdPattern) {
      this.resourceIdPattern = resourceIdPattern;
    }

    @Override
    public boolean match(ArnResource candidate) {
      return candidate.resourceType().isEmpty()
        && candidate.qualifier().isEmpty()
        && this.resourceIdPattern.match(candidate.resource());
    }

    @Override
    public String toString() {
      return this.resourceIdPattern.toString();
    }
  }

  final class ResourceTypeAndIDGlob implements ARNResourceMatcher {
    private final String resourceType;
    private final AWSGlob resourceId;

    private ResourceTypeAndIDGlob(String resourceType, AWSGlob resourceId) {
      this.resourceType = resourceType;
      this.resourceId = resourceId;
    }

    @Override
    public boolean match(ArnResource candidate) {
      return candidate.resourceType().isPresent()
        && candidate.resourceType().get().equals(this.resourceType)
        && candidate.qualifier().isEmpty()
        && this.resourceId.match(candidate.resource());
    }

    @Override
    public String toString() {
      return this.resourceType + ":" + this.resourceId;
    }
  }

  final class ResourceTypeAndIDGlobAndQualifierGlob implements ARNResourceMatcher {
    private final String resourceType;
    private final AWSGlob resourceId;
    private final AWSGlob qualifier;

    private ResourceTypeAndIDGlobAndQualifierGlob(String resourceType, AWSGlob resourceId, AWSGlob qualifier) {
      this.resourceType = resourceType;
      this.resourceId = resourceId;
      this.qualifier = qualifier;
    }

    @Override
    public boolean match(ArnResource candidate) {
      return candidate.resourceType().isPresent()
        && candidate.resourceType().get().equals(this.resourceType)
        && this.resourceId.match(candidate.resource())
        && candidate.qualifier().isPresent()
        && this.qualifier.match(candidate.qualifier().get());
    }

    @Override
    public String toString() {
      return this.resourceType + ":" + this.resourceId + ":" + this.qualifier;
    }
  }

  static class ResourceMatchSyntaxError extends Exception {
    ResourceMatchSyntaxError(String message) {
      super(message);
    }
  }

}
