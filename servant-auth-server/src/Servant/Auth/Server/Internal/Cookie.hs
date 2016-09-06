module Servant.Auth.Server.Internal.Cookie where

import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE          as Jose
import qualified Crypto.JWT           as Jose
import           Crypto.Util          (constTimeEq)
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BSL
import           Data.CaseInsensitive (CI)
import           Network.Wai          (requestHeaders)
import           Web.Cookie

import Servant.Auth.Server.Internal.JWT   (FromJWT (decodeJWT),
                                           JWTAuthConfig (..),
                                           defaultJWTAuthConfig)
import Servant.Auth.Server.Internal.Types


cookieAuthCheck :: FromJWT usr => CookieAuthConfig -> AuthCheck usr
cookieAuthCheck config = do
  req <- ask
  jwtCookie <- maybe mempty return $ do
    cookies' <- lookup "Cookie" $ requestHeaders req
    let cookies = parseCookies cookies'
    xsrfCookie <- lookup (xsrfCookieName config) cookies
    xsrfHeader <- lookup (xsrfHeaderName config) $ requestHeaders req
    guard $ xsrfCookie `constTimeEq` xsrfHeader
    -- JWT-Cookie *must* be HttpOnly and Secure
    lookup "JWT-Cookie" cookies
  verifiedJWT <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict jwtCookie
    let jwtCfg = jwtConfig config
    Jose.validateJWSJWT (jwtValidationSettings jwtCfg) (jwk jwtCfg) unverifiedJWT
    return unverifiedJWT
  case verifiedJWT of
    Left (_ :: Jose.JWTError) -> mzero
    Right v -> case decodeJWT v of
      Left _ -> mzero
      Right v' -> return v'

defaultCookieAuthConfig :: Jose.JWK -> CookieAuthConfig
defaultCookieAuthConfig key = CookieAuthConfig
  { xsrfCookieName        = "XSRF-TOKEN"
  , xsrfHeaderName        = "X-XSRF-TOKEN"
  , jwtConfig = defaultJWTAuthConfig key
  }


data CookieAuthConfig = CookieAuthConfig
  { xsrfCookieName :: BS.ByteString
  , xsrfHeaderName :: CI (BS.ByteString)
  , jwtConfig      :: JWTAuthConfig
  }
