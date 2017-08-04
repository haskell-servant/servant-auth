module Servant.Auth.Server.Internal.Cookie where

import           Blaze.ByteString.Builder (toByteString)
import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE              as Jose
import qualified Crypto.JWT               as Jose
import           Crypto.Util              (constTimeEq)
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Char8    as BSC
import qualified Data.ByteString.Base64   as BS64
import qualified Data.ByteString.Lazy     as BSL
import           Data.CaseInsensitive     (mk)
import           Data.Maybe               (fromMaybe, isJust)
import           Network.HTTP.Types       (methodGet)
import           Network.HTTP.Types.Header(hCookie)
import           Network.Wai              (Request, requestHeaders, requestMethod)
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
    cookies' <- lookup hCookie $ requestHeaders req
    let cookies = parseCookies cookies'
    -- Apply the XSRF check if enabled.
    guard $ case cookieXsrfSetting ccfg of
      Just xsrfCookieSettings -> xsrfCookieAuthCheck xsrfCookieSettings req cookies
      Nothing                 -> True
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

xsrfCookieAuthCheck :: XsrfCookieSettings -> Request -> [(BS.ByteString, BS.ByteString)] -> Bool
xsrfCookieAuthCheck xsrfCookieCfg req cookies = fromMaybe False $ do
  xsrfCookie <- lookup (xsrfCookieName xsrfCookieCfg) cookies
  xsrfHeader <- lookup (mk $ xsrfHeaderName xsrfCookieCfg) $ requestHeaders req
  guard checkEnabled
  return $ xsrfCookie `constTimeEq` xsrfHeader
  where
    checkDisabled = xsrfExcludeGet xsrfCookieCfg && requestMethod req == methodGet
    checkEnabled = not checkDisabled


-- | Makes a cookie to be used for XSRF.
makeXsrfCookie :: CookieSettings -> IO SetCookie
makeXsrfCookie cookieSettings = case cookieXsrfSetting cookieSettings of
  Just xsrfCookieSettings -> makeRealCookie xsrfCookieSettings
  Nothing                 -> return $ noXsrfTokenCookie cookieSettings
  where
    makeRealCookie xsrfCookieSettings = do
      xsrfValue <- BS64.encode <$> getEntropy 32
      return
        $ applyXsrfCookieSettings xsrfCookieSettings
        $ applyCookieSettings cookieSettings
        $ def{ setCookieValue = xsrfValue }


-- | Alias for 'makeXsrfCookie'.
makeCsrfCookie :: CookieSettings -> IO SetCookie
makeCsrfCookie = makeXsrfCookie
{-# DEPRECATED makeCsrfCookie "Use makeXsrfCookie instead" #-}


-- | Makes a cookie with session information.
makeSessionCookie :: ToJWT v => CookieSettings -> JWTSettings -> v -> IO (Maybe SetCookie)
makeSessionCookie cookieSettings jwtSettings v = do
  ejwt <- makeJWT v jwtSettings Nothing
  case ejwt of
    Left _ -> return Nothing
    Right jwt -> return
      $ Just
      $ applySessionCookieSettings cookieSettings
      $ applyCookieSettings cookieSettings
      $ def{ setCookieValue = BSL.toStrict jwt }

noXsrfTokenCookie :: CookieSettings -> SetCookie
noXsrfTokenCookie cookieSettings =
  applyCookieSettings cookieSettings $ def{ setCookieName = "NO-XSRF-TOKEN", setCookieValue = "" }

applyCookieSettings :: CookieSettings -> SetCookie -> SetCookie
applyCookieSettings cookieSettings setCookie = setCookie
  { setCookieMaxAge = cookieMaxAge cookieSettings
  , setCookieExpires = cookieExpires cookieSettings
  , setCookiePath = cookiePath cookieSettings
  , setCookieSecure = case cookieIsSecure cookieSettings of
      Secure -> True
      NotSecure -> False
  }

applyXsrfCookieSettings :: XsrfCookieSettings -> SetCookie -> SetCookie
applyXsrfCookieSettings xsrfCookieSettings setCookie = setCookie
  { setCookieName = xsrfCookieName xsrfCookieSettings
  , setCookiePath = xsrfCookiePath xsrfCookieSettings
  , setCookieHttpOnly = False
  }

applySessionCookieSettings :: CookieSettings -> SetCookie -> SetCookie
applySessionCookieSettings cookieSettings setCookie = setCookie
  { setCookieName = sessionCookieName cookieSettings
  , setCookieHttpOnly = True
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
      xsrfCookie <- makeXsrfCookie cookieSettings
      return $ Just $ addHeader sessionCookie . addHeader xsrfCookie

-- | Adds headers to a response that clears all session cookies.
clearSession :: ( AddHeader "Set-Cookie" SetCookie response withOneCookie
                , AddHeader "Set-Cookie" SetCookie withOneCookie withTwoCookies )
             => CookieSettings
             -> response
             -> withTwoCookies
clearSession cookieSettings
  = addHeader (applySessionCookieSettings cookieSettings $ applyCookieSettings cookieSettings def)
  . addHeader (noXsrfTokenCookie cookieSettings)

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
