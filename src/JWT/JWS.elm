module JWT.JWS exposing (DecodeError(..), Header, JWS, VerificationError(..), decode, fromParts, isValid)

import Base64.Decode as B64Decode
import Base64.Encode as B64Encode
import Bytes exposing (Bytes)
import Bytes.Encode
import Crypto.HMAC
import JWT.ClaimSet as ClaimSet exposing (VerifyOptions)
import JWT.JWK as JWK
import JWT.UrlBase64 as UrlBase64
import Json.Decode as Decode
import Json.Decode.Pipeline exposing (optional, required)
import Json.Encode as Encode
import Result exposing (andThen, map, mapError)
import Time exposing (Posix)
import Word.Bytes


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


type DecodeError
    = Base64DecodeError
    | InvalidHeader Decode.Error
    | InvalidClaims Decode.Error


fromParts : String -> String -> String -> Result DecodeError JWS
fromParts header claims signature =
    let
        decode_ d part =
            UrlBase64.decode (B64Decode.decode d) part
    in
    case
        ( decode_ B64Decode.string header
        , decode_ B64Decode.string claims
        , decode_ B64Decode.bytes signature
        )
    of
        ( Ok header_, Ok claims_, Ok signature_ ) ->
            decode header_ claims_ signature_

        _ ->
            Err Base64DecodeError


decode : String -> String -> Bytes -> Result DecodeError JWS
decode header claims signature =
    Decode.decodeString headerDecoder header
        |> mapError InvalidHeader
        |> andThen
            (\header_ ->
                Decode.decodeString ClaimSet.decoder claims
                    |> mapError InvalidClaims
                    |> map (JWS signature header_)
            )


encodeParts : JWS -> List String
encodeParts token =
    [ Encode.encode 0 <| headerEncoder token.header
    , Encode.encode 0 <| ClaimSet.encoder token.claims
    ]


headerDecoder : Decode.Decoder Header
headerDecoder =
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


headerEncoder : Header -> Encode.Value
headerEncoder header =
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


type VerificationError
    = UnsupportedAlgorithm
    | InvalidSignature
    | ClaimSet ClaimSet.VerificationError


isValid : VerifyOptions -> String -> Posix -> JWS -> Result VerificationError Bool
isValid options key now token =
    checkSignature key token
        |> Result.andThen
            (\_ ->
                ClaimSet.isValid options now token.claims
                    |> Result.mapError ClaimSet
            )


checkSignature : String -> JWS -> Result VerificationError Bool
checkSignature key token =
    let
        payload =
            encodeParts token
                |> List.map (\p -> UrlBase64.encode B64Encode.encode (B64Encode.string p))
                |> String.join "."
                |> Word.Bytes.fromUTF8

        calculated alg =
            Crypto.HMAC.digestBytes alg (Word.Bytes.fromUTF8 key) payload
                |> List.map Bytes.Encode.unsignedInt8
                |> Bytes.Encode.sequence
                |> Bytes.Encode.encode

        detectAlg =
            case token.header.alg of
                "HS256" ->
                    Ok Crypto.HMAC.sha256

                _ ->
                    Err UnsupportedAlgorithm
    in
    detectAlg
        |> Result.andThen
            (\alg ->
                if token.signature == calculated alg then
                    Ok True

                else
                    Err InvalidSignature
            )
