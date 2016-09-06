module Servant.Auth.Server.Internal.JWT where

import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE                        as Jose
import qualified Crypto.JWT                         as Jose
import           Crypto.Util                        (constTimeEq)
import           Data.Aeson                         (FromJSON, Result (..),
                                                     ToJSON, fromJSON, toJSON)
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as BSL
import qualified Data.HashMap.Strict                as HM
import qualified Data.Text                          as T
import           Network.Wai                        (requestHeaders)
import           Servant.Auth.Server.Internal.Types

-- This should probably also be from ClaimSet
class FromJWT a where
  decodeJWT :: Jose.JWT -> Either T.Text a
  default decodeJWT :: FromJSON a => Jose.JWT -> Either T.Text a
  decodeJWT m = case HM.lookup "dat" (Jose._unregisteredClaims $ Jose.jwtClaimsSet m ) of
    Nothing -> Left "Missing 'dat' claim"
    Just v  -> case fromJSON v of
      Error e -> Left $ T.pack e
      Success a -> Right a

class ToJWT a where
  encodeJWT :: a -> Jose.ClaimsSet
  default encodeJWT :: ToJSON a => a -> Jose.ClaimsSet
  encodeJWT a = Jose.addClaim "dat" (toJSON a) $ Jose.emptyClaimsSet

jwtAuthCheck :: FromJWT usr => JWTAuthConfig -> AuthCheck usr
jwtAuthCheck config = do
  req <- ask
  token <- maybe mempty return $ do
    authHdr <- lookup "Authorization" $ requestHeaders req
    let bearer = "Bearer "
        (mbearer, rest) = BS.splitAt (BS.length bearer) authHdr
    guard (mbearer `constTimeEq` bearer)
    return rest
  verifiedJWT <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict token
    Jose.validateJWSJWT (jwtValidationSettings config) (jwk config) unverifiedJWT
    return unverifiedJWT
  case verifiedJWT of
    Left (_ :: Jose.JWTError) -> mzero
    Right v -> case decodeJWT v of
      Left _ -> mzero
      Right v' -> return v'

data JWTAuthConfig = JWTAuthConfig
  { jwk                   :: Jose.JWK
  , jwtValidationSettings :: Jose.JWTValidationSettings
  }

defaultJWTAuthConfig :: Jose.JWK -> JWTAuthConfig
defaultJWTAuthConfig key = JWTAuthConfig
  { jwk                   = key
  , jwtValidationSettings = Jose.defaultJWTValidationSettings
  }
