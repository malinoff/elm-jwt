# JWT

Parse and verify JSON Web Tokens.

## Scope

The general plan is to have a fully RFC compliant, robust and reliable library that can parse, build, and verify
[JWS](https://package.elm-lang.org/packages/simonh1000/elm-jwt/7.0.0/) and
[JWE](https://tools.ietf.org/html/rfc7516#section-3.3), using all supported
[algorithms](https://tools.ietf.org/html/rfc7518).

This library's current scope is to be used in [Auth0](https://auth0.com/) client.
But the other use-cases are happily accepted.

Since [Auth0](https://auth0.com/) currently only uses JWS with two possible
algorithms: [HS256](https://tools.ietf.org/html/rfc7518#section-3.2)
and [RS256](https://tools.ietf.org/html/rfc7518#section-3.3), no more algorithms will be implemented in the nearest 
future. In fact, currently the only supported algorithm is `HS256` since there is no PKCS1 elm library which is required
to verify RSA-based signatures. Same for ECC (ellyptic curve cryptography) based algorithms. PRs are welcome!

## Example

```elm
import JWT
import Time

token = case JWT.fromString "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8" of
    Ok t ->
        t
    Err err ->
        Debug.todo "Handle error" err

verifyOptions =
    { issuer = Nothing
    , subject = Just "1234567890"
    , audience = Nothing
    , jwtID = Nothing
    , leeway = 0
    }
    
now =
    Time.millisToPosix 1558855500000
    
isValid =
    JWT.isValid verifyOptions "your-256-bit-secret" now token

-- Can also verify as a task:
verify =
    JWT.verify verifyOptions "your-256-bit-secret" token
```

Parsing and verification are intentionally two different steps so you can still parse tokens signed with 
unsupported algorithms. You just won't be able to verify them using this library, but you can implement your own 
verifiers.

## Why not...

### [simonh1000/elm-jwt](https://package.elm-lang.org/packages/simonh1000/elm-jwt/7.0.0/)

* Parses only the JWS claims (payload). There is a function to get the header, but it's not used by the library itself.
* The token's signature is silently ignored.
* Verification only considers the [exp](https://tools.ietf.org/html/rfc7519#section-4.1.4) field, although there are 
other [fields](https://tools.ietf.org/html/rfc7519#section-4.1) worth considering.
* Requires the user to provide a payload type with encoders and decoders, even if some fields are well-known and can 
be parsed without user's action.

### [JonRowe/elm-jwt](https://package.elm-lang.org/packages/JonRowe/elm-jwt/1.0.0/)

* This is a fork of the previous library, removing `HTTP` support. Same concerns are applied.

### [ktonon/elm-jsonwebsocket](https://package.elm-lang.org/packages/ktonon/elm-jsonwebtoken/1.0.4/)

* Requires the user to provide a payload type with encoders and decoders, even if some fields are well-known and can 
be parsed without user's action.
* Verifies the signature (which is good!), but using only HMAC-based algorithms.
* Does not verify the `exp` and other useful fields.

## License

This library is licensed under GNU Public License v3. 

Please, consider purchasing a proprietary license if you want to use it in your closed-source project without 
disclosing the code.
