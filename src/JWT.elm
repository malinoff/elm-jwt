module JWT exposing (ClaimSet, Error(..), JWSHeader, JWT(..), claimsDecoder, fromString, toString)

import Base64
import Dict exposing (Dict)
import JWT.JWK exposing (JWK, jwkDecoder, jwkEncoder)
import JWT.UrlBase64 as UrlBase64
import Json.Decode as Decode
import Json.Decode.Pipeline exposing (custom, optional, required)
import Json.Encode as Encode
import Task exposing (Task)
import Time


type JWT
    = JWS { header : JWSHeader, claims : ClaimSet, signature : String }
    | NestedJWS { header : JWSHeader, claims : JWT, signature : String }
    | JWE { header : JWEHeader, claims : ClaimSet, signature : String }
    | NestedJWE { header : JWEHeader, claims : JWT, signature : String }


type Error
    = TokenExpired
    | TokenPartsInvalid
    | TokenPartsBase64Error
    | TokenClaimsInvalid Decode.Error
    | TokenTypeUnknown
    | NestedTokenInvalid Error


fromString : String -> Result Error JWT
fromString string =
    case String.split "." string of
        [ header_, claims_, signature ] ->
            case ( UrlBase64.decode Base64.decode header_, Base64.decode claims_ ) of
                ( Ok header, Ok claims ) ->
                    decodeJWT header claims signature

                ( _, _ ) ->
                    Err TokenPartsBase64Error

        -- TODO [ header_, encryptedKey, iv, ciphertext, authenticationTag ]
        _ ->
            Err TokenPartsInvalid


toString : JWT -> String
toString token =
    let
        ( header, claims, signature ) =
            encodeJWT token
    in
    ([ header, claims ]
        |> List.map (UrlBase64.encode Base64.encode)
    )
        ++ [ signature ]
        |> String.join "."



-- Internals


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


type alias JWSHeader =
    { alg : String
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


decodeJWT : String -> String -> String -> Result Error JWT
decodeJWT header claims signature =
    let
        decodeClaims toJwt toError header_ decoder =
            decoder claims
                |> Result.map (\claims_ -> toJwt { header = header_, claims = claims_, signature = signature })
                |> Result.mapError toError

        decode toNestedJWT toJWT header_ =
            if header_.cty == Just "JWT" then
                decodeClaims toNestedJWT NestedTokenInvalid header_ <|
                    fromString

            else
                decodeClaims toJWT TokenClaimsInvalid header_ <|
                    Decode.decodeString claimsDecoder

        mapError result =
            case result of
                Ok v ->
                    v

                Err _ ->
                    Err TokenTypeUnknown
    in
    header
        |> Decode.decodeString
            (Decode.oneOf
                [ Decode.map (decode NestedJWE JWE) jweHeaderDecoder
                , Decode.map (decode NestedJWS JWS) jwsHeaderDecoder
                ]
            )
        |> mapError


encodeJWT : JWT -> ( String, String, String )
encodeJWT token =
    let
        encode =
            \headerEncoder claimsEncoder_ t ->
                ( Encode.encode 0 (headerEncoder t.header)
                , Encode.encode 0 (claimsEncoder_ t.claims)
                , t.signature
                )
    in
    case token of
        JWS t ->
            encode jwsHeaderEncoder claimsEncoder t

        NestedJWS t ->
            encode jwsHeaderEncoder (toString >> Encode.string) t

        JWE t ->
            encode jweHeaderEncoder claimsEncoder t

        NestedJWE t ->
            encode jweHeaderEncoder (toString >> Encode.string) t


claimsDecoder : Decode.Decoder ClaimSet
claimsDecoder =
    Decode.succeed ClaimSet
        |> optional "iss" (Decode.maybe Decode.string) Nothing
        |> optional "sub" (Decode.maybe Decode.string) Nothing
        |> optional "aud" (Decode.maybe Decode.string) Nothing
        |> optional "exp" (Decode.maybe Decode.int) Nothing
        |> optional "nbf" (Decode.maybe Decode.int) Nothing
        |> optional "iat" (Decode.maybe Decode.int) Nothing
        |> optional "jti" (Decode.maybe Decode.string) Nothing
        |> custom (Decode.dict Decode.value)


claimsEncoder : ClaimSet -> Encode.Value
claimsEncoder claims =
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


jwsHeaderDecoder : Decode.Decoder JWSHeader
jwsHeaderDecoder =
    Decode.succeed JWSHeader
        |> required "alg" Decode.string
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


jwsHeaderEncoder : JWSHeader -> Encode.Value
jwsHeaderEncoder header =
    [ header.alg |> (\f -> Just ( "alg", Encode.string f ))
    , header.jku |> Maybe.map (\f -> ( "jku", Encode.string f ))
    , header.jwk |> Maybe.map (\f -> ( "jwk", jwkEncoder f ))
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
