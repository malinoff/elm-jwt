module Tests exposing (all)

import Bytes.Encode
import Dict
import Expect
import JWT
import Json.Encode
import Test exposing (Test, describe, test)
import Time


all : Test
all =
    describe "JWS tests"
        [ describe "Serialization of valid tokens"
            [ test "fromString" <|
                \_ ->
                    JWT.fromString validJWSString
                        |> Expect.equal (Ok validJWS)
            ]
        , describe "Verification"
            [ test "isValid, valid token" <|
                \_ ->
                    JWT.isValid verifyOptions key now validJWS
                        |> Expect.equal (Ok True)
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
                |> List.map Bytes.Encode.unsignedInt8
                |> Bytes.Encode.sequence
                |> Bytes.Encode.encode
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
