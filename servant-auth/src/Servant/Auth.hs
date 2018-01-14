{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Servant.Auth where

import GHC.Generics (Generic)
import Data.String (IsString)
import Data.Text (Text)
import Crypto.Util (constTimeEq)
import Data.Semigroup ((<>))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Web.HttpApiData

-- | A compact JWT Token.
newtype Token a = Token { getToken :: BS.ByteString }
  deriving (Eq, Show, Read, Generic, IsString)

instance ToHttpApiData (Token a) where
  toUrlPiece = bsToText . getToken
  toHeader = ("Bearer " <>) . getToken
instance FromHttpApiData (Token a) where
  parseUrlPiece = pure . Token . textToBs
  parseHeader bs = do
    let bearer = "Bearer "
        (mbearer, token) = BS.splitAt (BS.length bearer) bs
    if mbearer `constTimeEq` bearer
    then pure $ Token token
    else fail "Missing bearer"


textToBs :: Text -> BS.ByteString
textToBs = B64.decodeLenient . encodeUtf8

bsToText :: BS.ByteString -> Text
bsToText = decodeUtf8 . B64.encode

-- * Authentication

-- | @Auth [auth1, auth2] val :> api@ represents an API protected *either* by
-- @auth1@ or @auth2@
data Auth (auths :: [*]) val

-- ** Combinators

-- | A JSON Web Token (JWT) in the the Authorization header:
--
--    @Authorization: Bearer <token>@
--
-- Note that while the token is signed, it is not encrypted. Therefore do not
-- keep in it any information you would not like the client to know.
--
-- JWTs are described in IETF's <https://tools.ietf.org/html/rfc7519 RFC 7519>
data JWT

-- | A cookie. The content cookie itself is a JWT. Another cookie is also used,
-- the contents of which are expected to be send back to the server in a
-- header, for CSRF protection.
data Cookie


-- We could use 'servant''s BasicAuth, but then we don't get control over the
-- documentation, and we'd have to polykind everything. (Also, we don't
-- currently depend on servant!)
--
-- | Basic Auth.
data BasicAuth

-- | Login via a form.
data FormLogin form
