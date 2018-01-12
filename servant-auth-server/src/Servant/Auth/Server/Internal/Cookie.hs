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

import Servant.Auth (Token(..))
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT         (FromJWT (decodeJWT), ToJWT,
                                                 makeJWT, parseJWT)
import Servant.Auth.Server.Internal.Types


cookieAuthCheck :: FromJWT usr => CookieSettings -> JWTSettings -> AuthCheck usr
cookieAuthCheck ccfg jwtCfg = do
  req <- ask
  cookies' <- maybe (fail "Cookie missing") pure $
    lookup "Cookie" $ requestHeaders req
  let cookies = parseCookies cookies'
  xsrfCookie <- maybe (fail "Missing XSRF cookie") pure $
    lookup (xsrfCookieName ccfg) cookies
  xsrfHeader <- maybe (fail "Missing XSRF header") pure $
    lookup (mk $ xsrfHeaderName ccfg) $ requestHeaders req
  unless (xsrfCookie `constTimeEq` xsrfHeader) $ fail "XSRF check failed"
  -- session cookie *must* be HttpOnly and Secure
  case lookup (sessionCookieName ccfg) cookies of
    Just bs -> parseJWT jwtCfg $ Token bs
    Nothing -> fail "Session cookie missing"


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
makeSessionCookie :: (Jose.MonadRandom m, ToJWT v)
  => CookieSettings -> JWTSettings -> v -> m (Maybe SetCookie)
makeSessionCookie cookieSettings jwtSettings v = do
  eToken <- makeJWT v jwtSettings Nothing
  case eToken of
    Left _ -> return Nothing
    Right token -> return $ Just $ def
      { setCookieName = sessionCookieName cookieSettings
      , setCookieValue = getToken token
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
