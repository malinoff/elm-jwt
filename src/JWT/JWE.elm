module JWT.JWE exposing (JWEHeader, jweHeaderDecoder, jweHeaderEncoder)

import JWT.JWK exposing (JWK)


type alias JWEHeader =
    { alg : String
    , enc : String
    , zip : Maybe String
    , jku : Maybe String
    , jwk : Maybe JWK
    , kid : Maybe String
    , x5u : Maybe String
    , x5c : Maybe (List String)
    , x5t : Maybe String
    , x5t_S256 : Maybe String
    , typ : Maybe String
    , cty : Maybe String
    , crit : Maybe (List String)
    }


jweHeaderDecoder : Decode.Decoder JWEHeader
jweHeaderDecoder =
    Decode.succeed JWEHeader
        |> required "alg" Decode.string
        |> required "enc" Decode.string
        |> optional "zip" (Decode.maybe Decode.string) Nothing
        |> optional "jku" (Decode.maybe Decode.string) Nothing
        |> optional "jwk" (Decode.maybe jwkDecoder) Nothing
        |> optional "kid" (Decode.maybe Decode.string) Nothing
        |> optional "x5u" (Decode.maybe Decode.string) Nothing
        |> optional "x5c" (Decode.maybe <| Decode.list Decode.string) Nothing
        |> optional "x5t" (Decode.maybe Decode.string) Nothing
        |> optional "x5t#S256" (Decode.maybe Decode.string) Nothing
        |> optional "typ" (Decode.maybe Decode.string) Nothing
        |> optional "cty" (Decode.maybe Decode.string) Nothing
        |> optional "crit" (Decode.maybe <| Decode.list Decode.string) Nothing


jweHeaderEncoder : JWEHeader -> Encode.Value
jweHeaderEncoder header =
    [ header.alg |> (\f -> Just ( "alg", Encode.string f ))
    , header.enc |> (\f -> Just ( "enc", Encode.string f ))
    , header.zip |> Maybe.map (\f -> ( "zip", Encode.string f ))
    , header.jku |> Maybe.map (\f -> ( "jku", Encode.string f ))
    , header.jwk |> Maybe.map (\f -> ( "jwk", jwkEncoder f ))
    , header.kid |> Maybe.map (\f -> ( "jwk", Encode.string f ))
    , header.x5u |> Maybe.map (\f -> ( "jwk", Encode.string f ))
    , header.x5c |> Maybe.map (\f -> ( "jwk", Encode.list Encode.string f ))
    , header.x5t |> Maybe.map (\f -> ( "jwk", Encode.string f ))
    , header.x5t_S256 |> Maybe.map (\f -> ( "jwk", Encode.string f ))
    , header.typ |> Maybe.map (\f -> ( "jwk", Encode.string f ))
    , header.cty |> Maybe.map (\f -> ( "jwk", Encode.string f ))
    , header.crit |> Maybe.map (\f -> ( "jwk", Encode.list Encode.string f ))
    ]
        |> List.filterMap identity
        |> Encode.object
