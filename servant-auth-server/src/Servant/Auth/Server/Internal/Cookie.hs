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
import           Servant                  (AddHeader, addHeader)
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
    Jose.verifyClaims (jwtSettingsToJwtValidationSettings jwtCfg)
                      (key jwtCfg)
                      unverifiedJWT
  case verifiedJWT of
    Left (_ :: Jose.JWTError) -> mzero
    Right v -> case decodeJWT v of
      Left _ -> mzero
      Right v' -> return v'

-- | Makes a cookie to be used for CSRF.
makeCsrfCookie :: CookieSettings -> IO SetCookie
makeCsrfCookie cookieSettings = do
  csrfValue <- BS64.encode <$> getEntropy 32
  return $ def
    { setCookieName = xsrfCookieName cookieSettings
    , setCookieValue = csrfValue
    , setCookieMaxAge = cookieMaxAge cookieSettings
    , setCookieExpires = cookieExpires cookieSettings
    , setCookiePath = xsrfCookiePath cookieSettings
    , setCookieSecure = case cookieIsSecure cookieSettings of
        Secure -> True
        NotSecure -> False
    }

-- | Makes a cookie with session information.
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
      , setCookiePath = cookiePath cookieSettings
      , setCookieSecure = case cookieIsSecure cookieSettings of
          Secure -> True
          NotSecure -> False
      }

-- | For a JWT-serializable session, returns a function that decorates a
-- provided response object with CSRF and session cookies. This should be used
-- when a user successfully authenticates with credentials.
acceptLogin :: ( ToJWT session
               , AddHeader "Set-Cookie" SetCookie response withOneCookie
               , AddHeader "Set-Cookie" SetCookie withOneCookie withTwoCookies )
            => CookieSettings
            -> JWTSettings
            -> session
            -> IO (Maybe (response -> withTwoCookies))
acceptLogin cookieSettings jwtSettings session = do
  mSessionCookie <- makeSessionCookie cookieSettings jwtSettings session
  case mSessionCookie of
    Nothing            -> pure Nothing
    Just sessionCookie -> do
      csrfCookie <- makeCsrfCookie cookieSettings
      return $ Just $ addHeader sessionCookie . addHeader csrfCookie

makeSessionCookieBS :: ToJWT v => CookieSettings -> JWTSettings -> v -> IO (Maybe BS.ByteString)
makeSessionCookieBS a b c = fmap (toByteString . renderSetCookie)  <$> makeSessionCookie a b c

-- | Alias for 'makeSessionCookie'.
makeCookie :: ToJWT v => CookieSettings -> JWTSettings -> v -> IO (Maybe SetCookie)
makeCookie = makeSessionCookie
{-# DEPRECATED makeCookie "Use makeSessionCookie instead" #-}

-- | Alias for 'makeSessionCookieBS'.
makeCookieBS :: ToJWT v => CookieSettings -> JWTSettings -> v -> IO (Maybe BS.ByteString)
makeCookieBS = makeSessionCookieBS
{-# DEPRECATED makeCookieBS "Use makeSessionCookieBS instead" #-}
