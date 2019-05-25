module JWT exposing (Error(..), JWT(..), fromString, toString)

import Base64.Decode
import Base64.Encode
import JWT.JWS as JWS
import JWT.UrlBase64 as UrlBase64


type JWT
    = JWS JWS.JWS


type Error
    = TokenTypeUnknown
    | JWSError JWS.Error


fromString : String -> Result Error JWT
fromString string =
    case String.split "." string of
        [ header, claims, signature ] ->
            JWS.fromParts header claims signature
                |> Result.mapError JWSError
                |> Result.map JWS

        -- TODO [ header_, encryptedKey, iv, ciphertext, authenticationTag ]
        _ ->
            Err TokenTypeUnknown


toString : JWT -> String
toString token =
    String.join "." <|
        List.map (UrlBase64.encode Base64.Encode.encode) <|
            case token of
                JWS t ->
                    JWS.toParts t



--signJWS : String -> {a | header : JWSHeader, claims : ClaimSet, signature : String } -> Result String String
--signJWS key { header, claims, signature } =
--    if signature /= "" then
--        signature
--    else
--        case header.alg of
--            "HS256" ->
--
--            "HS384" ->
--
--            "HS512" ->
--
--            "RS256" ->
--
--            "RS384" ->
--
--            "RS512" ->
--
--            "ES256" ->
--
--            "ES384" ->
--
--            "ES512" ->
--
--            "PS256" ->
--
--            "PS384" ->
--
--            alg ->
--                Err "Unsupported alg: " ++ alg
