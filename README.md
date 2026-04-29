# kafka-sasl-x-cram-sts
Kafka `X-CRAM-STS` SASL Mechanism

## Overview

The `X-CRAM-STS` SASL mechanism uses AWS's Security Token Service to provide secure Kafka client authentication.

## Mechanism Sequence Specification

### Client ####

The client sends the ASCII sequence:
```declarative
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
```declarative
[authzid]\0x00[presigned_url]
```

as is response to the server. Note that `\0x00` indicates the `NUL` octet, not a literal string sequence.

The `authzid` is the authorization identity the client asserts it has access to. Because fetching a presigned STS
GetCallerIdentity URL returns the authentication identity used to presign the URL, no separate `authcid` needs
communicating.

This is the terminal production in the `X-CRAM-STS` mechanism-specific sequence.
