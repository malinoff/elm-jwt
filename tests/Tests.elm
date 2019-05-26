module Tests exposing (all)

import Dict
import Expect
import JWT
import JWT.JWS
import Json.Encode
import Test exposing (Test, describe, test)
import Time


all : Test
all =
    describe "JWS tests"
        [ describe "fromString"
            [ test "Valid token" <|
                \_ ->
                    JWT.fromString validJWSString
                        |> Expect.equal (Ok validJWS)
            , test "Invalid token: empty string" <|
                \_ ->
                    JWT.fromString ""
                        |> Expect.equal (Err JWT.TokenTypeUnknown)
            , test "Invalid token: wrong number of parts" <|
                \_ ->
                    JWT.fromString "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ"
                        |> Expect.equal (Err JWT.TokenTypeUnknown)
            , test "Invalid token: not a base64url" <|
                \_ ->
                    JWT.fromString (String.replace "ey" "" validJWSString)
                        |> Expect.equal (Err (JWT.JWSError JWT.JWS.Base64DecodeError))
            ]
        , describe "isValid"
            [ test "Valid token" <|
                \_ ->
                    JWT.isValid verifyOptions key now validJWS
                        |> Expect.equal (Ok True)
            , test "Invalid token: unsigned" <|
                \_ ->
                    JWT.isValid verifyOptions key now unsignedJWS
                        |> Expect.equal (Err (JWT.JWSVerificationError JWT.JWS.InvalidSignature))
            , test "Invalid token: insecure" <|
                \_ ->
                    JWT.isValid verifyOptions key now insecureJWS
                        |> Expect.equal (Err (JWT.JWSVerificationError JWT.JWS.UnsupportedAlgorithm))
            ]
        ]


validJWSString =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8"


validJWS =
    JWT.JWS
        { header =
            { alg = "HS256"
            , jku = Nothing
            , jwk = Nothing
            , kid = Nothing
            , x5u = Nothing
            , x5c = Nothing
            , x5t = Nothing
            , x5t_S256 = Nothing
            , typ = Just "JWT"
            , cty = Nothing
            , crit = Nothing
            }
        , claims =
            { iss = Nothing
            , sub = Just "1234567890"
            , aud = Nothing
            , exp = Nothing
            , nbf = Nothing
            , iat = Just 1516239022
            , jti = Nothing
            , metadata =
                Dict.fromList
                    [ ( "sub", Json.Encode.string "1234567890" )
                    , ( "iat", Json.Encode.int 1516239022 )
                    , ( "name", Json.Encode.string "John Doe" )
                    ]
            }
        , signature =
            [ 125, 211, 143, 67, 78, 89, 125, 24, 100, 73, 61, 190, 172, 133, 160, 82, 150, 234, 82, 197, 97, 146, 67, 85, 53, 203, 134, 236, 168, 180, 179, 239 ]
        }


unsignedJWS =
    JWT.JWS
        { header =
            { alg = "HS256"
            , jku = Nothing
            , jwk = Nothing
            , kid = Nothing
            , x5u = Nothing
            , x5c = Nothing
            , x5t = Nothing
            , x5t_S256 = Nothing
            , typ = Just "JWT"
            , cty = Nothing
            , crit = Nothing
            }
        , claims =
            { iss = Nothing
            , sub = Just "1234567890"
            , aud = Nothing
            , exp = Nothing
            , nbf = Nothing
            , iat = Just 1516239022
            , jti = Nothing
            , metadata =
                Dict.fromList
                    [ ( "sub", Json.Encode.string "1234567890" )
                    , ( "iat", Json.Encode.int 1516239022 )
                    , ( "name", Json.Encode.string "John Doe" )
                    ]
            }
        , signature =
            []
        }


insecureJWS =
    JWT.JWS
        { header =
            { alg = "none"
            , jku = Nothing
            , jwk = Nothing
            , kid = Nothing
            , x5u = Nothing
            , x5c = Nothing
            , x5t = Nothing
            , x5t_S256 = Nothing
            , typ = Just "JWT"
            , cty = Nothing
            , crit = Nothing
            }
        , claims =
            { iss = Nothing
            , sub = Just "1234567890"
            , aud = Nothing
            , exp = Nothing
            , nbf = Nothing
            , iat = Just 1516239022
            , jti = Nothing
            , metadata =
                Dict.fromList
                    [ ( "sub", Json.Encode.string "1234567890" )
                    , ( "iat", Json.Encode.int 1516239022 )
                    , ( "name", Json.Encode.string "John Doe" )
                    ]
            }
        , signature =
            []
        }


verifyOptions =
    { issuer = Nothing
    , audience = Nothing
    , subject = Just "1234567890"
    , jwtID = Nothing
    , leeway = 0
    }


now =
    Time.millisToPosix 1558855500


key =
    "your-256-bit-secret"
