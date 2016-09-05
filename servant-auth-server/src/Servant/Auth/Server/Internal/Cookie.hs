module Servant.Auth.Server.Internal.Cookie where

import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE          as Jose
import qualified Crypto.JWT           as Jose
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BSL
import           Data.CaseInsensitive (CI)
import           Network.Wai          (requestHeaders)
import           Web.Cookie

import Servant.Auth.Server.Internal.JWT (FromJWT(decodeJWT))
import Servant.Auth.Server.Internal.Types


cookieAuthCheck :: FromJWT usr => CookieAuthConfig -> AuthCheck usr
cookieAuthCheck config = do
  req <- ask
  jwtCookie <- maybe mempty return $ do
    cookies' <- lookup "Cookie" $ requestHeaders req
    let cookies = parseCookies cookies'
    xsrfCookie <- lookup (xsrfCookieName config) cookies
    xsrfHeader <- lookup (xsrfHeaderName config) $ requestHeaders req
    guard $ xsrfCookie == xsrfHeader
    -- JWT-Cookie *must* be HttpOnly and Secure
    lookup "JWT-Cookie" cookies
  val <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict jwtCookie
    Jose.validateJWSJWT (jwtValidationSettings config) (jwk config) unverifiedJWT
    return $ decodeJWT unverifiedJWT
  either (\(_ :: Jose.JWTError) -> mzero) return val

defaultCookieAuthConfig :: Jose.JWK -> CookieAuthConfig
defaultCookieAuthConfig key = CookieAuthConfig
  { jwk                   = key
  , xsrfCookieName        = "XSRF-TOKEN"
  , xsrfHeaderName        = "X-XSRF-TOKEN"
  , jwtValidationSettings = Jose.defaultJWTValidationSettings
  }


data CookieAuthConfig = CookieAuthConfig
  { jwk                   :: Jose.JWK
  , xsrfCookieName        :: BS.ByteString
  , xsrfHeaderName        :: CI (BS.ByteString)
  , jwtValidationSettings :: Jose.JWTValidationSettings
  }
