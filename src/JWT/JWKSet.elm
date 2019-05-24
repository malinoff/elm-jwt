module JWT.JWKSet exposing (JWKSet, fromString, jwkSetDecoder, jwkSetEncoder, toString)

import JWT.JWK exposing (JWK, jwkDecoder, jwkEncoder)
import Json.Decode as Decode
import Json.Encode as Encode


type alias JWKSet =
    { keys : List JWK }


fromString : String -> Result Decode.Error JWKSet
fromString string =
    Decode.decodeString jwkSetDecoder string


toString : JWKSet -> String
toString jwks =
    jwkSetEncoder jwks |> Encode.encode 0


jwkSetEncoder : JWKSet -> Encode.Value
jwkSetEncoder { keys } =
    Encode.object
        [ ( "keys", Encode.list jwkEncoder keys ) ]


jwkSetDecoder : Decode.Decoder JWKSet
jwkSetDecoder =
    Decode.list jwkDecoder
        |> Decode.field "keys"
        |> Decode.map JWKSet
