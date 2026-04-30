package com.mister_webhooks.sasl.x_cram_sts.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.SaslException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Set;
import java.util.stream.Collectors;

public final class URIEvaluator {
  private static final Logger logger = LoggerFactory.getLogger(URIEvaluator.class);

  private final URI presignedURI;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;

  private URIEvaluator(URI validatedURI) {
    this.presignedURI = validatedURI;
    this.httpClient = HttpClient.newHttpClient();
    this.objectMapper = new ObjectMapper();
  }

  @NotNull
  @Contract("_ -> new")
  public static URIEvaluator fromURI(String uriString) throws SecurityException, URISyntaxException {
    URIBuilder uri = new URIBuilder(uriString);

    if (!uri.getScheme().equals("https")) {
      throw new SecurityException("GetCallerIdentity URI must use https");
    }

    if (!(uri.getHost().matches("sts\\.[-a-z0-9]+\\.amazonaws\\.com") || uri.getHost().equals("sts.amazonaws.com"))) {
      throw new SecurityException("GetCallerIdentity URI must be for sts.*.amazonaws.com or sts.amazonaws.com");
    }

    Set<NameValuePair> actionParams = uri.getQueryParams()
      .stream()
      .filter(nvp -> nvp.getName().equalsIgnoreCase("ACTION"))
      .collect(Collectors.toSet());

    if (actionParams.size() != 1) {
      throw new SecurityException(String.format(
        "GetCallerIdentity URI must have exactly one Action parameter, got: %s",
        actionParams));
    }

    NameValuePair action = actionParams.stream().toList().getFirst();

    if (!(action.getName().equalsIgnoreCase("ACTION") && action.getValue().equals("GetCallerIdentity"))) {
      throw new SecurityException("GetCallerIdentity URI must have Action=GetCallerIdentity as a query param");
    }

    if (uri.getQueryParams()
      .stream()
      .filter(nvp ->
        nvp.getName().equalsIgnoreCase("x-amz-signedheaders")
      ).count() != 1) {
      throw new SecurityException("X-Amz-SignedHeaders must occur exactly once");
    }

    if (uri.getQueryParams()
      .stream()
      .filter(nvp ->
        nvp.getName().equalsIgnoreCase("x-amz-signedheaders")
          && nvp.getValue().equals("challenge;host")
      ).count() != 1) {
      throw new SecurityException("X-Amz-SignedHeaders must be 'challenge;host'");
    }

    return new URIEvaluator(uri.build());
  }

  public URI getURI() {
    return this.presignedURI;
  }

  public String execute(String challenge) throws SaslException {
    HttpRequest request;
    HttpResponse<String> stsResponse;

    request = HttpRequest.newBuilder()
      .uri(this.presignedURI)
      .header("Accept", "application/json")
      .header("Challenge", challenge)
      .build();

    try {
      stsResponse = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    } catch (IOException | InterruptedException e) {
      throw new SaslException(e.toString());
    }

    //noinspection MagicNumber
    if (stsResponse.statusCode() != 200) {
      throw new SaslException(stsResponse.toString());
    }

    try {
      JsonNode root = this.objectMapper.readTree(stsResponse.body());
      return root.get("GetCallerIdentityResponse").get("GetCallerIdentityResult").get("Arn").textValue();
    } catch (JsonProcessingException e) {
      throw new SaslException(e.toString());
    }
  }

  public static final class SecurityException extends Exception {
    private SecurityException(String message) {
      super(message);
    }
  }
}
