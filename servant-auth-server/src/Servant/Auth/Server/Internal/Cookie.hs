module Servant.Auth.Server.Internal.Cookie where

import           Blaze.ByteString.Builder (toByteString)
import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE              as Jose
import qualified Crypto.JWT               as Jose
import           Crypto.Util              (constTimeEq)
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Base64   as BS64
import qualified Data.ByteString.Lazy     as BSL
import           Data.CaseInsensitive     (mk)
import           Network.Wai              (requestHeaders)
import           System.Entropy           (getEntropy)
import           Web.Cookie

import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT         (FromJWT (decodeJWT), ToJWT,
                                                 makeJWT)
import Servant.Auth.Server.Internal.Types


cookieAuthCheck :: FromJWT usr => CookieSettings -> JWTSettings -> AuthCheck usr
cookieAuthCheck ccfg jwtCfg = do
  req <- ask
  jwtCookie <- maybe mempty return $ do
    cookies' <- lookup "Cookie" $ requestHeaders req
    let cookies = parseCookies cookies'
    xsrfCookie <- lookup (xsrfCookieName ccfg) cookies
    xsrfHeader <- lookup (mk $ xsrfHeaderName ccfg) $ requestHeaders req
    guard $ xsrfCookie `constTimeEq` xsrfHeader
    -- session cookie *must* be HttpOnly and Secure
    lookup (sessionCookieName ccfg) cookies
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

makeCsrfCookie :: CookieSettings -> IO SetCookie
makeCsrfCookie cookieSettings = do
  csrfValue <- BS64.encode <$> getEntropy 32
  return $ def
    { setCookieName = xsrfCookieName cookieSettings
    , setCookieValue = csrfValue
    , setCookieMaxAge = cookieMaxAge cookieSettings
    , setCookieExpires = cookieExpires cookieSettings
    , setCookieSecure = case cookieIsSecure cookieSettings of
        Secure -> True
        NotSecure -> False
    }

makeSessionCookie :: ToJWT v => CookieSettings -> JWTSettings -> v -> IO (Maybe SetCookie)
makeSessionCookie cookieSettings jwtSettings v = do
  ejwt <- makeJWT v jwtSettings Nothing
  case ejwt of
    Left _ -> return Nothing
    Right jwt -> return $ Just $ def
      { setCookieName = sessionCookieName cookieSettings
      , setCookieValue = BSL.toStrict jwt
      , setCookieHttpOnly = True
      , setCookieMaxAge = cookieMaxAge cookieSettings
      , setCookieExpires = cookieExpires cookieSettings
      , setCookieSecure = case cookieIsSecure cookieSettings of
          Secure -> True
          NotSecure -> False
      }

-- Publicly-exposed function
makeCookie :: ToJWT v => CookieSettings -> JWTSettings -> v -> IO (Maybe SetCookie)
makeCookie = makeSessionCookie

makeCookieBS :: ToJWT v => CookieSettings -> JWTSettings -> v -> IO (Maybe BS.ByteString)
makeCookieBS a b c = fmap (toByteString . renderSetCookie)  <$> makeCookie a b c
