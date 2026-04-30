# kafka-sasl-x-cram-sts
Kafka `X-CRAM-STS` SASL Mechanism

## Overview

The `X-CRAM-STS` SASL mechanism uses AWS's Security Token Service's GetCallerIdentity facility to provide secure Kafka client authentication.

## Configuration

### Add `X-CRAM-STS` to Kafka broker enabled mechanism list

Add `X-CRAM-STS` to the list of enabled SASL mechanisms on the broker. To use both `PLAIN` passwords and `X-CRAM-STS`:
```properties
sasl.enabled.mechanisms=PLAIN,X-CRAM-STS
```

### Configure `X-CRAM-STS` for each listener

If you have a listener called `foobar`, you'll need to add the following lines:
```properties
listener.name.foobar.x-cram-sts.sasl.jaas.config=com.mister_webhooks.sasl.x_cram_sts.LoginModule required;
listener.name.foobar.x-cram-sts.sasl.server.callback.handler.class=com.mister_webhooks.sasl.x_cram_sts.ServerCallbackHandler
listener.name.foobar.x-cram-sts.sasl.login.callback.handler.class=com.mister_webhooks.sasl.x_cram_sts.ServerCallbackHandler
```

Sadly, this must be configured for each listener you have defined on the broker without exception or default.

### Configure ARN patterns for users

Almost done! For each Kafka user you want to authenticate, you'll need to set up a username -> ARN pattern mapping under
the `com.mister_webhooks.security.user.iam` namespace.

Here's an example:
```properties
com.mister_webhooks.security.user.iam.someuser=arn:aws:iam:::role/myrole1,arn:aws:iam:::role/myrole2
```

This says that a client that wants to authenticate as `someuser` may do so by sending a authentication token for either
`arn:aws:iam:::role/myrole1` or `arn:aws:iam:::role/myrole2`.

ARN patterns are substantially similar to AWS's own ARN matching syntax, but with the following caveats:
1. If `*` is used, it must be alone. For example: `arn:aws:iam:*:123456789012:role/myrole` matches the `myrole` role in account `123456789012` in any region, but `arn:aws:iam:us-west-*:123456789012:role/myrole` is not valid.
2. A pattern like `*-something-*` is not supported.
3. IAM `role` matchers are auto-expanded to match the corresponding STS `assumed-role`.

### Optional: Set the challenge size

The size of the challenge the server sends the client can be configured (even if there's no clear reason to do so). The
default is 32 octets.

```properties
com.mister_webhooks.sasl.x_cram_sts.server.challenge_size=32
```

## Mechanism Sequence Specification

### Client ####

The client sends the ASCII sequence:
```
HENLO FREN
```

### Server ####

The server responds to `HENLO FREN` with a sequence of octets that are HTTP header-safe (values between 0x21 and 0x7c).

To prevent token reuse attacks, an implementation MUST send a unique and unpredictable sequence for each SASL exchange.

### Client ####

The client incorporates the challenge sequence as the `challenge` HTTP header for the AWS STS presigner. It generates an
STS `GetCallerIdentity` presigned URL with the header.

For example, using the Golang AWS SDK:

```golang
presigned, err := presignClient.PresignGetCallerIdentity(
    ctx,
    &sts.GetCallerIdentityInput{},
    func(po *sts.PresignOptions) {
        po.ClientOptions = append(po.ClientOptions, func(o *sts.Options) {
            o.Interceptors.AddBeforeSigning(&InjectHeader{"challenge", string(challenge)})
        })
    },
)
```

The client sends:
```
[authzid]\0x00[presigned_url]
```

as its response to the server. Note that `\0x00` indicates the `NUL` octet, not a literal string sequence.

The `authzid` is the authorization identity the client asserts it has access to. Because fetching a presigned STS
GetCallerIdentity URL returns the authentication identity used to presign the URL, no separate `authcid` needs
communicating.

This is the terminal production in the `X-CRAM-STS` mechanism-specific sequence.
