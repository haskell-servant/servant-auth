module Servant.Auth.Server.Internal.JWT where

import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE                        as Jose
import qualified Crypto.JWT                         as Jose
import           Data.Aeson                         (FromJSON, Result (..),
                                                     ToJSON, Value, fromJSON,
                                                     toJSON)
import qualified Data.ByteString                    as BS
import qualified Data.ByteString.Lazy               as BSL
import qualified Data.HashMap.Strict                as HM
import qualified Data.Text                          as T
import           Network.Wai                        (requestHeaders)
import           Servant.Auth.Server.Internal.Types

class FromJWT a where
  decodeJWT :: Jose.JWT -> Either T.Text a
  default decodeJWT :: FromJSON a => Jose.JWT -> Either T.Text a
  decodeJWT m = case HM.lookup "dat" (Jose._unregisteredClaims $ Jose.jwtClaimsSet m ) of
    Nothing -> Left "Missing 'dat' claim"
    Just v  -> case fromJSON v of
      Error e -> Left $ T.pack e
      Success a -> Right a

class ToJWT a where
  encodeJWT :: a -> Jose.JWT
  default encodeJWT :: ToJSON a => a -> HM.HashMap T.Text Value
  encodeJWT a = HM.fromList $ [("dat", toJSON a)]

jwtAuthCheck :: FromJWT usr => JWTAuthConfig -> AuthCheck usr
jwtAuthCheck config = do
  req <- ask
  token <- maybe mempty return $ do
    authHdr <- lookup "Authorization" $ requestHeaders req
    let bearer = "Bearer "
        (mbearer, rest) = BS.splitAt (BS.length bearer) authHdr
    guard (mbearer == bearer)
    return rest
  verifiedJWT <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict token
    Jose.validateJWSJWT (jwtValidationSettings config) (jwk config) unverifiedJWT
    return unverifiedJWT
  case verifiedJWT >>= decodeJWT of
    Left _ -> mzero
    Right v -> return v
  {-either (const mzero) return $ decodeJWT verifiedJWT-}

data JWTAuthConfig = JWTAuthConfig
  { jwk                   :: Jose.JWK
  , jwtValidationSettings :: Jose.JWTValidationSettings
  }

defaultJWTAuthConfig :: Jose.JWK -> JWTAuthConfig
defaultJWTAuthConfig key = JWTAuthConfig
  { jwk                   = key
  , jwtValidationSettings = Jose.defaultJWTValidationSettings
  }
