module JWT.ClaimSet exposing (ClaimSet, decoder, encoder)

import Dict exposing (Dict)
import Json.Decode as Decode
import Json.Decode.Pipeline exposing (custom, optional)
import Json.Encode as Encode


type alias ClaimSet =
    { iss : Maybe String
    , sub : Maybe String
    , aud : Maybe String
    , exp : Maybe Int
    , nbf : Maybe Int
    , iat : Maybe Int
    , jti : Maybe String
    , metadata : Dict String Decode.Value
    }


decoder : Decode.Decoder ClaimSet
decoder =
    Decode.succeed ClaimSet
        |> optional "iss" (Decode.maybe Decode.string) Nothing
        |> optional "sub" (Decode.maybe Decode.string) Nothing
        |> optional "aud" (Decode.maybe Decode.string) Nothing
        |> optional "exp" (Decode.maybe Decode.int) Nothing
        |> optional "nbf" (Decode.maybe Decode.int) Nothing
        |> optional "iat" (Decode.maybe Decode.int) Nothing
        |> optional "jti" (Decode.maybe Decode.string) Nothing
        |> custom (Decode.dict Decode.value)


encoder : ClaimSet -> Encode.Value
encoder claims =
    let
        metadata =
            Dict.toList claims.metadata
                |> List.map Just
    in
    metadata
        ++ [ claims.iss |> Maybe.map (\f -> ( "iss", Encode.string f ))
           , claims.sub |> Maybe.map (\f -> ( "sub", Encode.string f ))
           , claims.aud |> Maybe.map (\f -> ( "aud", Encode.string f ))
           , claims.exp |> Maybe.map (\f -> ( "exp", Encode.int f ))
           , claims.nbf |> Maybe.map (\f -> ( "nbf", Encode.int f ))
           , claims.iat |> Maybe.map (\f -> ( "iat", Encode.int f ))
           , claims.jti |> Maybe.map (\f -> ( "jti", Encode.string f ))
           ]
        |> List.filterMap identity
        |> Encode.object
