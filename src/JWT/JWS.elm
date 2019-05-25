module JWT.JWS exposing (Error(..), Header, JWS, decode, decoder, encode, encoder, fromParts, toParts)

import Base64.Decode as B64Decode
import Base64.Encode as B64Encode
import Bytes exposing (Bytes)
import JWT.ClaimSet as ClaimSet
import JWT.JWK as JWK
import JWT.UrlBase64 as UrlBase64
import Json.Decode as Decode
import Json.Decode.Pipeline exposing (optional, required)
import Json.Encode as Encode
import Result exposing (andThen, map, mapError)


type alias JWS =
    { signature : Bytes
    , header : Header
    , claims : ClaimSet.ClaimSet
    }


type alias Header =
    { alg : String
    , jku : Maybe String
    , jwk : Maybe JWK.JWK
    , kid : Maybe String
    , x5u : Maybe String
    , x5c : Maybe (List String)
    , x5t : Maybe String
    , x5t_S256 : Maybe String
    , typ : Maybe String
    , cty : Maybe String
    , crit : Maybe (List String)
    }


type Error
    = Base64DecodeError
    | InvalidHeader Decode.Error
    | InvalidClaims Decode.Error


fromParts : String -> String -> String -> Result Error JWS
fromParts header claims signature =
    let
        header_ =
            UrlBase64.decode (B64Decode.decode B64Decode.string) header

        claims_ =
            UrlBase64.decode (B64Decode.decode B64Decode.string) claims

        signature_ =
            UrlBase64.decode (B64Decode.decode B64Decode.bytes) signature
    in
    case ( header_, claims_, signature_ ) of
        ( Ok h, Ok c, Ok s ) ->
            decode h c s

        _ ->
            Err Base64DecodeError


toParts : JWS -> List String
toParts token =
    let
        ( header, claims, signature ) =
            encode token
    in
    [ UrlBase64.encode B64Encode.encode (B64Encode.string header)
    , UrlBase64.encode B64Encode.encode (B64Encode.string claims)
    , UrlBase64.encode B64Encode.encode (B64Encode.bytes signature)
    ]


decode : String -> String -> Bytes -> Result Error JWS
decode header claims signature =
    Decode.decodeString decoder header
        |> mapError InvalidHeader
        |> andThen
            (\header_ ->
                Decode.decodeString ClaimSet.decoder claims
                    |> mapError InvalidClaims
                    |> map (JWS signature header_)
            )


encode : JWS -> ( String, String, Bytes )
encode token =
    ( Encode.encode 0 <| encoder token.header
    , Encode.encode 0 <| ClaimSet.encoder token.claims
    , token.signature
    )


decoder : Decode.Decoder Header
decoder =
    Decode.succeed Header
        |> required "alg" Decode.string
        |> optional "jku" (Decode.maybe Decode.string) Nothing
        |> optional "jwk" (Decode.maybe JWK.decoder) Nothing
        |> optional "kid" (Decode.maybe Decode.string) Nothing
        |> optional "x5u" (Decode.maybe Decode.string) Nothing
        |> optional "x5c" (Decode.maybe <| Decode.list Decode.string) Nothing
        |> optional "x5t" (Decode.maybe Decode.string) Nothing
        |> optional "x5t#S256" (Decode.maybe Decode.string) Nothing
        |> optional "typ" (Decode.maybe Decode.string) Nothing
        |> optional "cty" (Decode.maybe Decode.string) Nothing
        |> optional "crit" (Decode.maybe <| Decode.list Decode.string) Nothing


encoder : Header -> Encode.Value
encoder header =
    [ header.alg |> (\f -> Just ( "alg", Encode.string f ))
    , header.jku |> Maybe.map (\f -> ( "jku", Encode.string f ))
    , header.jwk |> Maybe.map (\f -> ( "jwk", JWK.encoder f ))
    , header.kid |> Maybe.map (\f -> ( "kid", Encode.string f ))
    , header.x5u |> Maybe.map (\f -> ( "x5u", Encode.string f ))
    , header.x5c |> Maybe.map (\f -> ( "x5c", Encode.list Encode.string f ))
    , header.x5t |> Maybe.map (\f -> ( "x5t", Encode.string f ))
    , header.x5t_S256 |> Maybe.map (\f -> ( "x5t#S256", Encode.string f ))
    , header.typ |> Maybe.map (\f -> ( "typ", Encode.string f ))
    , header.cty |> Maybe.map (\f -> ( "cty", Encode.string f ))
    , header.crit |> Maybe.map (\f -> ( "crit", Encode.list Encode.string f ))
    ]
        |> List.filterMap identity
        |> Encode.object
