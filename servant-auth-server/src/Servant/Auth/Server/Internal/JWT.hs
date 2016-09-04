module Servant.Auth.Server.Internal.JWT where

import           Control.Monad.Except
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BSL
import           Network.Wai          (requestHeaders)
import qualified Crypto.JOSE          as Jose
import           Control.Monad.Reader
import qualified Crypto.JWT                         as Jose
import           Servant.Auth.Server.Internal.Types

class FromJWT a where
  decodeJWT :: Jose.JWT -> a

class ToJWT a where
  encodeJWT :: a -> Jose.JWT

jwtAuthCheck :: FromJWT usr => JWTAuthConfig -> AuthCheck usr
jwtAuthCheck config = do
  req <- ask
  token <- maybe mempty return $ do
    authHdr <- lookup "Authorization" $ requestHeaders req
    let bearer = "Bearer "
        (mbearer, rest) = BS.splitAt (BS.length bearer) authHdr
    guard (mbearer == bearer)
    return rest
  val <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict token
    Jose.validateJWSJWT (jwtValidationSettings config) (jwk config) unverifiedJWT
    return $ decodeJWT unverifiedJWT
  either (\(_ :: Jose.JWTError) -> mzero) return val

data JWTAuthConfig = JWTAuthConfig
  { jwk :: Jose.JWK
  , jwtValidationSettings :: Jose.JWTValidationSettings
  }
