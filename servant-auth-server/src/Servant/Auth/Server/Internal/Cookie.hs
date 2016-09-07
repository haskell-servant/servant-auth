module Servant.Auth.Server.Internal.Cookie where

import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE          as Jose
import qualified Crypto.JWT           as Jose
import           Crypto.Util          (constTimeEq)
import qualified Data.ByteString.Lazy as BSL
import           Data.CaseInsensitive (mk)
import           Network.Wai          (requestHeaders)
import           Web.Cookie

import Servant.Auth.Server.Internal.JWT   (FromJWT (decodeJWT))
import Servant.Auth.Server.Internal.Types
import Servant.Auth.Server.Internal.ConfigTypes


cookieAuthCheck :: FromJWT usr => CookieSettings -> JWTSettings -> AuthCheck usr
cookieAuthCheck ccfg jwtCfg = do
  req <- ask
  jwtCookie <- maybe mempty return $ do
    cookies' <- lookup "Cookie" $ requestHeaders req
    let cookies = parseCookies cookies'
    xsrfCookie <- lookup (xsrfCookieName ccfg) cookies
    xsrfHeader <- lookup (mk $ xsrfHeaderName ccfg) $ requestHeaders req
    guard $ xsrfCookie `constTimeEq` xsrfHeader
    -- JWT-Cookie *must* be HttpOnly and Secure
    lookup "JWT-Cookie" cookies
  verifiedJWT <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict jwtCookie
    Jose.validateJWSJWT (jwtSettingsToJwtValidationSettings jwtCfg)
                        (key jwtCfg)
                         unverifiedJWT
    return unverifiedJWT
  case verifiedJWT of
    Left (_ :: Jose.JWTError) -> mzero
    Right v -> case decodeJWT v of
      Left _ -> mzero
      Right v' -> return v'

{-
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
-}
