module JWT exposing (DecodeError(..), JWT(..), VerificationError(..), fromString, isValid)

import JWT.ClaimSet exposing (VerifyOptions)
import JWT.JWS as JWS
import Time exposing (Posix)


type JWT
    = JWS JWS.JWS


type DecodeError
    = TokenTypeUnknown
    | JWSError JWS.DecodeError


fromString : String -> Result DecodeError JWT
fromString string =
    case String.split "." string of
        [ header, claims, signature ] ->
            JWS.fromParts header claims signature
                |> Result.mapError JWSError
                |> Result.map JWS

        -- TODO [ header_, encryptedKey, iv, ciphertext, authenticationTag ]
        _ ->
            Err TokenTypeUnknown


type VerificationError
    = JWSVerificationError JWS.VerificationError


isValid : VerifyOptions -> String -> Posix -> JWT -> Result VerificationError Bool
isValid options key now token =
    case token of
        JWS token_ ->
            JWS.isValid options key now token_
                |> Result.mapError JWSVerificationError
