module Tests exposing (all)

import Dict
import Expect
import JWT
import Json.Encode
import Test exposing (Test, describe, test)


all : Test
all =
    describe "JWS tests"
        [ describe "Serialization of valid tokens"
            [ test "fromString" <|
                \_ ->
                    JWT.fromString validJWSString
                        |> Expect.equal (Ok validJWS)
            , test "toString" <|
                \_ ->
                    JWT.toString validJWS
                        |> Expect.equal validJWSString
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
        , signature = "fdOPQ05ZfRhkST2-rIWgUpbqUsVhkkNVNcuG7Ki0s-8"
        }
